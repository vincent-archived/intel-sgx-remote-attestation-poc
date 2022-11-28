#![crate_name = "mra"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate sgx_tcrypto;
extern crate sgx_trts;
extern crate sgx_tse;
extern crate sgx_types;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate sgx_rand;

extern crate base64;
extern crate bit_vec;
extern crate chrono;
extern crate crypto;
extern crate httparse;
extern crate itertools;
extern crate num_bigint;
extern crate rustls;
extern crate serde_json;
extern crate webpki;
extern crate webpki_roots;
extern crate yasna;

use sgx_tse::*;
use sgx_types::*;
use std::backtrace::{self, PrintFormat};
//use sgx_trts::trts::{rsgx_raw_is_outside_enclave, rsgx_lfence};
use sgx_rand::*;
use sgx_tcrypto::*;

use crypto::Address;
use crypto::KeyManager;
use crypto::Signer;
use crypto::Verifier;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::prelude::v1::*;
use std::ptr;
use std::str;
use std::string::String;
use std::sync::Arc;
use std::untrusted::fs;
use std::vec::Vec;

mod cert;
mod hex;

pub const DEV_HOSTNAME: &'static str = "api.trustedservices.intel.com";
pub const SIGRL_SUFFIX: &'static str = "/sgx/dev/attestation/v3/sigrl/";
pub const REPORT_SUFFIX: &'static str = "/sgx/dev/attestation/v3/report";
pub const CERTEXPIRYDAYS: i64 = 90i64;

extern "C" {
    pub fn ocall_sgx_init_quote(
        ret_val: *mut sgx_status_t,
        ret_ti: *mut sgx_target_info_t,
        ret_gid: *mut sgx_epid_group_id_t,
    ) -> sgx_status_t;
    pub fn ocall_get_ias_socket(ret_val: *mut sgx_status_t, ret_fd: *mut i32) -> sgx_status_t;
    pub fn ocall_get_quote(
        ret_val: *mut sgx_status_t,
        p_sigrl: *const u8,
        sigrl_len: u32,
        p_report: *const sgx_report_t,
        quote_type: sgx_quote_sign_type_t,
        p_spid: *const sgx_spid_t,
        p_nonce: *const sgx_quote_nonce_t,
        p_qe_report: *mut sgx_report_t,
        p_quote: *mut u8,
        maxlen: u32,
        p_quote_len: *mut u32,
    ) -> sgx_status_t;
}

fn parse_response_attn_report(resp: &[u8]) -> (String, String, String) {
    println!("Logs: Parse response attn report \n");
    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut respp = httparse::Response::new(&mut headers);
    let result = respp.parse(resp);
    // println!("parse result {:?}", result);

    //println!("{}", msg);
    let mut len_num: u32 = 0;

    let mut sig = String::new();
    let mut cert = String::new();
    let mut attn_report = String::new();

    for i in 0..respp.headers.len() {
        let h = respp.headers[i];
        //println!("{} : {}", h.name, str::from_utf8(h.value).unwrap());
        match h.name {
            "Content-Length" => {
                let len_str = String::from_utf8(h.value.to_vec()).unwrap();
                len_num = len_str.parse::<u32>().unwrap();
                // println!("content length = {}", len_num);
            }
            "X-IASReport-Signature" => sig = str::from_utf8(h.value).unwrap().to_string(),
            "X-IASReport-Signing-Certificate" => {
                cert = str::from_utf8(h.value).unwrap().to_string()
            }
            _ => (),
        }
    }

    // Remove %0A from cert, and only obtain the signing cert
    cert = cert.replace("%0A", "");
    cert = cert::percent_decode(cert);
    let v: Vec<&str> = cert.split("-----").collect();
    let sig_cert = v[2].to_string();

    if len_num != 0 {
        let header_len = result.unwrap().unwrap();
        let resp_body = &resp[header_len..];
        attn_report = str::from_utf8(resp_body).unwrap().to_string();
        println!("Logs: Attestation report: {} \n", attn_report);
    }

    // len_num == 0
    (attn_report, sig, sig_cert)
}

fn parse_response_sigrl(resp: &[u8]) -> Vec<u8> {
    println!("Logs: Parse response sigrl \n");
    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut respp = httparse::Response::new(&mut headers);
    let result = respp.parse(resp);
    //println!("parse result {:?}", result);
    //println!("parse response{:?}", respp);

    // println!("{}", msg);
    let mut len_num: u32 = 0;

    for i in 0..respp.headers.len() {
        let h = respp.headers[i];
        if h.name == "content-length" {
            let len_str = String::from_utf8(h.value.to_vec()).unwrap();
            len_num = len_str.parse::<u32>().unwrap();
            // println!("content length = {}", len_num);
        }
    }

    if len_num != 0 {
        let header_len = result.unwrap().unwrap();
        let resp_body = &resp[header_len..];
        println!("Base64-encoded SigRL: {:?} \n", resp_body);

        return base64::decode(str::from_utf8(resp_body).unwrap()).unwrap();
    }

    if len_num == 0 {
        println!("Logs: This EPID group ID Successful \n");
    }

    // len_num == 0
    Vec::new()
}

pub fn make_ias_client_config() -> rustls::ClientConfig {
    let mut config = rustls::ClientConfig::new();

    config
        .root_store
        .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

    config
}

pub fn get_sigrl_from_intel(fd: c_int, gid: u32) -> Vec<u8> {
    //println!("get_sigrl_from_intel fd = {:?}", fd);
    let config = make_ias_client_config();
    //let sigrl_arg = SigRLArg { group_id : gid };
    //let sigrl_req = sigrl_arg.to_httpreq();
    let ias_key = get_ias_api_key();

    let req = format!("GET {}{:08x} HTTP/1.1\r\nHOST: {}\r\nOcp-Apim-Subscription-Key: {}\r\nConnection: Close\r\n\r\n",
                        SIGRL_SUFFIX,
                        gid,
                        DEV_HOSTNAME,
                        ias_key);
    println!("{}", req);

    let dns_name = webpki::DNSNameRef::try_from_ascii_str(DEV_HOSTNAME).unwrap();
    let mut sess = rustls::ClientSession::new(&Arc::new(config), dns_name);
    let mut sock = TcpStream::new(fd).unwrap();
    let mut tls = rustls::Stream::new(&mut sess, &mut sock);

    let _result = tls.write(req.as_bytes());
    let mut plaintext = Vec::new();

    // println!("write complete");

    match tls.read_to_end(&mut plaintext) {
        Ok(_) => (),
        Err(e) => {
            println!("get_sigrl_from_intel tls.read_to_end: {:?}", e);
            panic!("haha");
        }
    }
    // println!("read_to_end complete");
    let resp_string = String::from_utf8(plaintext.clone()).unwrap();

    // println!("{}", resp_string);

    parse_response_sigrl(&plaintext)
}

// TODO: support pse
pub fn get_report_from_intel(fd: c_int, quote: Vec<u8>) -> (String, String, String) {
    println!("Logs: Start verify quote from intel ias server \n");
    // println!("get_report_from_intel fd = {:?}", fd);
    let config = make_ias_client_config();
    let encoded_quote = base64::encode(&quote[..]);
    println!("Logs: Generate quote to json \n");
    let encoded_json = format!("{{\"isvEnclaveQuote\":\"{}\"}}\r\n", encoded_quote);

    let ias_key = get_ias_api_key();

    let req = format!("POST {} HTTP/1.1\r\nHOST: {}\r\nOcp-Apim-Subscription-Key:{}\r\nContent-Length:{}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
                           REPORT_SUFFIX,
                           DEV_HOSTNAME,
                           ias_key,
                           encoded_json.len(),
                           encoded_json);
    println!("{}", req);
    let dns_name = webpki::DNSNameRef::try_from_ascii_str(DEV_HOSTNAME).unwrap();
    let mut sess = rustls::ClientSession::new(&Arc::new(config), dns_name);
    let mut sock = TcpStream::new(fd).unwrap();
    let mut tls = rustls::Stream::new(&mut sess, &mut sock);

    let _result = tls.write(req.as_bytes());
    let mut plaintext = Vec::new();

    // println!("write complete");

    tls.read_to_end(&mut plaintext).unwrap();
    // println!("read_to_end complete");
    let resp_string = String::from_utf8(plaintext.clone()).unwrap();

    // println!("resp_string = {}", resp_string);

    let (attn_report, sig, cert) = parse_response_attn_report(&plaintext);

    (attn_report, sig, cert)
}

fn as_u32_le(array: &[u8; 4]) -> u32 {
    ((array[0] as u32) << 0)
        + ((array[1] as u32) << 8)
        + ((array[2] as u32) << 16)
        + ((array[3] as u32) << 24)
}

#[allow(const_err)]
pub fn create_attestation_report(
    report_data: &sgx_report_data_t,
    sign_type: sgx_quote_sign_type_t,
) -> Result<(String, String, String), sgx_status_t> {
    // Workflow:
    // (1) ocall to get the target_info structure (ti) and epid group id (eg)
    // (1.5) get sigrl
    // (2) call sgx_create_report with ti+data, produce an sgx_report_t
    // (3) ocall to sgx_get_quote to generate (*mut sgx-quote_t, uint32_t)

    // (1) get ti + eg
    let mut ti: sgx_target_info_t = sgx_target_info_t::default();
    let mut eg: sgx_epid_group_id_t = sgx_epid_group_id_t::default();
    let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;

    println!("Logs: Generate enclave target info \n");

    let res = unsafe {
        ocall_sgx_init_quote(
            &mut rt as *mut sgx_status_t,
            &mut ti as *mut sgx_target_info_t,
            &mut eg as *mut sgx_epid_group_id_t,
        )
    };

    if res != sgx_status_t::SGX_SUCCESS {
        return Err(res);
    }

    if rt != sgx_status_t::SGX_SUCCESS {
        return Err(rt);
    }

    let eg_num = as_u32_le(&eg);

    // (1.5) get sigrl
    let mut ias_sock: i32 = 0;

    let res =
        unsafe { ocall_get_ias_socket(&mut rt as *mut sgx_status_t, &mut ias_sock as *mut i32) };

    if res != sgx_status_t::SGX_SUCCESS {
        return Err(res);
    }

    if rt != sgx_status_t::SGX_SUCCESS {
        return Err(rt);
    }

    //println!("Got ias_sock = {}", ias_sock);

    // Now sigrl_vec is the revocation list, a vec<u8>

    // (2) Generate the report
    // Fill ecc256 public key into report_data
    // let mut report_data: sgx_report_data_t = sgx_report_data_t::default();
    // let mut pub_k_gx = pub_k.gx.clone();
    // pub_k_gx.reverse();
    // let mut pub_k_gy = pub_k.gy.clone();
    // pub_k_gy.reverse();
    // report_data.d[..32].clone_from_slice(&pub_k_gx);
    // report_data.d[32..].clone_from_slice(&pub_k_gy);

    let rep = match rsgx_create_report(&ti, &report_data) {
        Ok(r) => {
            println!("Log: Use enclave target info generat report creation success, This report mr_signer = {:?} \n ", r.body.mr_signer.m);
            Some(r)
        }
        Err(e) => {
            println!("Log: Report creation => failed {:?}", e);
            None
        }
    };

    println!("Logs: Get sigrl from intel \n");
    println!("Logs: Local eg = {:?} \n", eg);
    let sigrl_vec: Vec<u8> = get_sigrl_from_intel(ias_sock, eg_num);

    let mut quote_nonce = sgx_quote_nonce_t { rand: [0; 16] };
    let mut os_rng = os::SgxRng::new().unwrap();
    os_rng.fill_bytes(&mut quote_nonce.rand);
    // println!("rand finished");
    let mut qe_report = sgx_report_t::default();
    const RET_QUOTE_BUF_LEN: u32 = 2048;
    let mut return_quote_buf: [u8; RET_QUOTE_BUF_LEN as usize] = [0; RET_QUOTE_BUF_LEN as usize];
    let mut quote_len: u32 = 0;

    // (3) Generate the quote
    // Args:
    //       1. sigrl: ptr + len
    //       2. report: ptr 432bytes
    //       3. linkable: u32, unlinkable=0, linkable=1
    //       4. spid: sgx_spid_t ptr 16bytes
    //       5. sgx_quote_nonce_t ptr 16bytes
    //       6. p_sig_rl + sigrl size ( same to sigrl)
    //       7. [out]p_qe_report need further check
    //       8. [out]p_quote
    //       9. quote_size
    let (p_sigrl, sigrl_len) = if sigrl_vec.len() == 0 {
        (ptr::null(), 0)
    } else {
        (sigrl_vec.as_ptr(), sigrl_vec.len() as u32)
    };
    let p_report = (&rep.unwrap()) as *const sgx_report_t;
    let quote_type = sign_type;

    let spid: sgx_spid_t = load_spid("spid.txt");

    let p_spid = &spid as *const sgx_spid_t;
    let p_nonce = &quote_nonce as *const sgx_quote_nonce_t;
    let p_qe_report = &mut qe_report as *mut sgx_report_t;
    let p_quote = return_quote_buf.as_mut_ptr();
    let maxlen = RET_QUOTE_BUF_LEN;
    let p_quote_len = &mut quote_len as *mut u32;

    let result = unsafe {
        ocall_get_quote(
            &mut rt as *mut sgx_status_t,
            p_sigrl,
            sigrl_len,
            p_report,
            quote_type,
            p_spid,
            p_nonce,
            p_qe_report,
            p_quote,
            maxlen,
            p_quote_len,
        )
    };

    if result != sgx_status_t::SGX_SUCCESS {
        return Err(result);
    }

    if rt != sgx_status_t::SGX_SUCCESS {
        println!("ocall_get_quote returned {}", rt);
        return Err(rt);
    }

    // Added 09-28-2018
    // Perform a check on qe_report to verify if the qe_report is valid
    match rsgx_verify_report(&qe_report) {
        Ok(()) => println!("Logs: rsgx_verify_report passed! \n"),
        Err(x) => {
            println!("rsgx_verify_report failed with {:?}", x);
            return Err(x);
        }
    }

    // Check if the qe_report is produced on the same platform
    if ti.mr_enclave.m != qe_report.body.mr_enclave.m
        || ti.attributes.flags != qe_report.body.attributes.flags
        || ti.attributes.xfrm != qe_report.body.attributes.xfrm
    {
        println!("qe_report does not match current target_info!");
        return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
    }

    println!("Logs: qe_report check passed! \n");

    // Debug
    // for i in 0..quote_len {
    //     print!("{:02X}", unsafe {*p_quote.offset(i as isize)});
    // }
    // println!("");

    // Check qe_report to defend against replay attack
    // The purpose of p_qe_report is for the ISV enclave to confirm the QUOTE
    // it received is not modified by the untrusted SW stack, and not a replay.
    // The implementation in QE is to generate a REPORT targeting the ISV
    // enclave (target info from p_report) , with the lower 32Bytes in
    // report.data = SHA256(p_nonce||p_quote). The ISV enclave can verify the
    // p_qe_report and report.data to confirm the QUOTE has not be modified and
    // is not a replay. It is optional.

    let mut rhs_vec: Vec<u8> = quote_nonce.rand.to_vec();
    rhs_vec.extend(&return_quote_buf[..quote_len as usize]);
    let rhs_hash = rsgx_sha256_slice(&rhs_vec[..]).unwrap();
    let lhs_hash = &qe_report.body.report_data.d[..32];

    // println!("rhs hash = {:02X}", rhs_hash.iter().format(""));
    // println!("report hs= {:02X}", lhs_hash.iter().format(""));

    if rhs_hash != lhs_hash {
        println!("Logs: Quote is tampered!");
        return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
    }

    let quote_vec: Vec<u8> = return_quote_buf[..quote_len as usize].to_vec();
    let res =
        unsafe { ocall_get_ias_socket(&mut rt as *mut sgx_status_t, &mut ias_sock as *mut i32) };

    println!("Logs: Quote data => \n{:?}\n", &quote_vec);

    if res != sgx_status_t::SGX_SUCCESS {
        return Err(res);
    }

    if rt != sgx_status_t::SGX_SUCCESS {
        return Err(rt);
    }

    let (attn_report, sig, cert) = get_report_from_intel(ias_sock, quote_vec.clone());

    let sgx_quote: sgx_quote_t = unsafe { ptr::read(quote_vec.as_ptr() as *const _) };

    let data = sgx_quote.report_body.report_data.d.clone();

    let address = Address::from(&data[..20]);

    println!(
        "Logs: sgx quote report_data public key hex {:?}",
        address.to_hex_string()
    );

    // Borrow of packed field is unsafe in future Rust releases
    // ATTENTION
    // DO SECURITY CHECK ON DEMAND
    // DO SECURITY CHECK ON DEMAND
    // DO SECURITY CHECK ON DEMAND
    
        println!("Logs: sgx quote version = {}", sgx_quote.version);
        println!("Logs: sgx quote signature type = {}", sgx_quote.sign_type);
        println!(
            "Logs: sgx quote report_data = {:?}",
            sgx_quote.report_body.report_data.d
        );
        println!(
            "Logs: sgx quote mr_enclave = {:?}",
            sgx_quote.report_body.mr_enclave.m
        );
        println!(
            "Logs: sgx quote mr_signer = {:?}",
            sgx_quote.report_body.mr_signer.m
        );
    
    Ok((attn_report, sig, cert))
}

fn load_spid(filename: &str) -> sgx_spid_t {
    let mut spidfile = fs::File::open(filename).expect("cannot open spid file");
    let mut contents = String::new();
    spidfile
        .read_to_string(&mut contents)
        .expect("cannot read the spid file");

    hex::decode_spid(&contents)
}

fn get_ias_api_key() -> String {
    let mut keyfile = fs::File::open("key.txt").expect("cannot open ias key file");
    let mut key = String::new();
    keyfile
        .read_to_string(&mut key)
        .expect("cannot read the ias key file");

    key.trim_end().to_owned()
}



#[no_mangle]
pub extern "C" fn run_poc(sign_type: sgx_quote_sign_type_t) -> sgx_status_t {
    let _ = backtrace::enable_backtrace("enclave.signed.so", PrintFormat::Short);

    let rust_raw_string = "Logs: This is a in-Enclave Rust string! \n";

    let hello_string = String::from(rust_raw_string);

    println!("{}", &hello_string);

    let mut key_manager = KeyManager::new(String::from("/home/ubuntu/"));

    let kp = match key_manager.get_enclave_key() {
        Some(kp) => {
            println!("Logs: Has been created enclave key, now read! \n");
            kp
        }
        None => {
            println!("Logs: Not found enclave key, now create \n");
            key_manager.create_enclave_key().unwrap()
        }
    };

    println!("Logs: Get enclave public key! \n");

    println!(
        "{:?} \n\nBytes: {:?} \n",
        kp.get_pubkey(),
        kp.get_pubkey().as_bytes()
    );
    println!(
        "Hex: {} \n",
        Address::from(&kp.get_pubkey()).to_hex_string()
    );

    println!("Logs: Sign some things msg! \n");

    let some_things_msg = "hello world!";

    let sign_msg = Signer::sign(kp, &some_things_msg.as_bytes());

    println!("{:?}  \n", sign_msg);

    println!("Logs: Verify sign msg! \n");

    let verify = Verifier::verify(
        &kp.get_pubkey(),
        &some_things_msg.as_bytes(),
        &sign_msg.unwrap(),
    );

    println!("{:?}  \n", verify);

    // let spid = "2F4648F96EF4F9CD433D1B8DB8C33E38";

    // let pk = "19f4076a892e4a9683288e8c824eeaf2";

    // let sk = "19f4076a892e4a9683288e8c824eeaf2";

    println!("Logs: Generate sgx report body is include enclave public key! \n");

    // let target_info : sgx_target_info_t = sgx_target_info_t::default();

    // let eg : sgx_epid_group_id_t = sgx_epid_group_id_t::default();

    let report_data = kp.get_pubkey().as_report_data();

    // let report = rsgx_create_report(&target_info, &report_data).unwrap();

    // println!("Logs:  Report creation => success {:?}", report.body.mr_signer.m);

    let (attn_report, sig, cert) = match create_attestation_report(&report_data, sign_type) {
        Ok(r) => r,
        Err(e) => {
            println!("Error in create_attestation_report: {:?}", e);
            return e;
        }
    };

    sgx_status_t::SGX_SUCCESS
}
