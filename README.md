## 总览
![](https://docs.lcp.network/assets/images/remote-attestation-5b648793abb56c1bcb64d02828771ad2.png)

## 步骤详解

#### 1. Send InitEnclaveCommand

App 和 Enclave 创建

```
[+] Init Enclave Successful 2!
Logs: This is a in-Enclave Rust string! 
```

#### 2. Generate Enclave Key

启动时判断是否已经生成过私钥，如果已经生成则使用 SGX 读取。 如果未读取到则调用 SGX 随机数发生器，调用 libsecp256k1-sgx 库生成公私钥，私钥使用 SGX 密封保存。然后测试签名验签是否正常。

```
Logs: Has been created enclave key, now read! 

Logs: Get enclave public key! 

EnclavePublicKey(PublicKey(Affine { x: Field { n: [80807, 19696501, 1781662, 23077581, 45415550, 39153554, 41941805, 5207957, 40693373, 823325], magnitude: 1, normalized: false }, y: Field { n: [31617144, 4544564, 42533665, 27772383, 19643801, 50745896, 31307533, 54110940, 27384169, 770119], magnitude: 1, normalized: false }, infinity: false })) 

Bytes: [2, 50, 64, 118, 108, 238, 125, 19, 221, 229, 103, 255, 178, 217, 85, 190, 74, 180, 252, 126, 88, 8, 179, 65, 178, 249, 228, 178, 45, 212, 1, 59, 167] 

Logs: Sign some things msg! 

Ok([185, 183, 60, 100, 51, 62, 177, 76, 206, 17, 237, 1, 181, 52, 97, 79, 221, 169, 165, 70, 112, 214, 105, 144, 120, 214, 142, 253, 130, 54, 82, 105, 120, 100, 55, 36, 145, 189, 47, 146, 20, 75, 226, 48, 174, 119, 252, 115, 255, 68, 36, 78, 66, 63, 106, 32, 42, 196, 196, 65, 210, 58, 213, 4, 0])  

Logs: Verify sign msg! 

Ok(())  
```

#### 3. Create Report that includes Enclave Key

把公钥放进 report_data，生成 enclave 环境度量值 target_info，使用这两个值生成本地可验证的 report。

```
pub struct sgx_target_info_t {
        /* (  0) The MRENCLAVE of the target enclave */
        pub mr_enclave: sgx_measurement_t,
        /* ( 32) The ATTRIBUTES field of the target enclave */
        pub attributes: sgx_attributes_t,
        /* ( 48) Reserved */
        pub reserved1: [uint8_t; SGX_TARGET_INFO_RESERVED1_BYTES],
        /* ( 50) CONFIGSVN field */
        pub config_svn: sgx_config_svn_t,
        /* ( 52) The MISCSELECT of the target enclave */
        pub misc_select: sgx_misc_select_t,
        /* ( 56) Reserved */
        pub reserved2: [uint8_t; SGX_TARGET_INFO_RESERVED2_BYTES],
        /* ( 64) CONFIGID */
        pub config_id: sgx_config_id_t,
        /* (128) Struct size is 512 bytes */
        pub reserved3: [uint8_t; SGX_TARGET_INFO_RESERVED3_BYTES],
}
```

```
/* 432 bytes */
pub struct sgx_report_t { 
        pub body: sgx_report_body_t,
        /* (384) KeyID used for diversifying the key tree */
        pub key_id: sgx_key_id_t,
        /* (416) The Message Authentication Code over this structure. */
        pub mac: sgx_mac_t,
}

pub struct sgx_report_body_t {
        /* (  0) Security Version of the CPU */
        pub cpu_svn: sgx_cpu_svn_t,
        /* ( 16) Which fields defined in SSA.MISC */
        pub misc_select: sgx_misc_select_t,
        /* ( 20) */
        pub reserved1: [uint8_t; SGX_REPORT_BODY_RESERVED1_BYTES],
        /* ( 32) ISV assigned Extended Product ID */
        pub isv_ext_prod_id: sgx_isvext_prod_id_t,
        /* ( 48) Any special Capabilities the Enclave possess */
        pub attributes: sgx_attributes_t,
        /* ( 64) The value of the enclave's ENCLAVE measurement */
        pub mr_enclave: sgx_measurement_t,
        /* ( 96) */
        pub reserved2: [uint8_t; SGX_REPORT_BODY_RESERVED2_BYTES],
        /* (128) The value of the enclave's SIGNER measurement */
        pub mr_signer: sgx_measurement_t,
        /* (160) */
        pub reserved3: [uint8_t; SGX_REPORT_BODY_RESERVED3_BYTES],
        /* (192) CONFIGID */
        pub config_id: sgx_config_id_t,
        /* (256) Product ID of the Enclave */
        pub isv_prod_id: sgx_prod_id_t,
        /* (258) Security Version of the Enclave */
        pub isv_svn: sgx_isv_svn_t,
        /* (260) CONFIGSVN */
        pub config_svn: sgx_config_svn_t,
        /* (262) */
        pub reserved4: [uint8_t; SGX_REPORT_BODY_RESERVED4_BYTES],
        /* (304) ISV assigned Family ID */
        pub isv_family_id: sgx_isvfamily_id_t,
        /* (320) Data provided by the user */
        pub report_data: sgx_report_data_t,
    }

```



```
Logs: Generate sgx report body is include enclave public key! 

Logs: Generate enclave target info 

Log: Use enclave target info generat report creation success, This report mr_signer = [131, 215, 25, 231, 125, 234, 202, 20, 112, 246, 186, 246, 42, 77, 119, 67, 3, 200, 153, 219, 105, 2, 15, 156, 112, 238, 29, 252, 8, 199, 206, 158] 
```



#### 4. Return report

生成的 report 返回给 app，读取本地  EPID group 版本并调用接口发送给 Intel，Intel 返回本地硬件是否可信，如果返回错误，则终止下一步流程。CPU 硬件可通过微码更新更新到新版本，Intel 通过微码修复安全问题。

```
Logs: Get sigrl from intel 

Logs: Local eg = [75, 12, 0, 0] 

GET /sgx/dev/attestation/v3/sigrl/00000c4b HTTP/1.1
HOST: api.trustedservices.intel.com
Ocp-Apim-Subscription-Key: 19f4076a892e4a9683288e8c824eeaf2
Connection: Close


Logs: Parse response sigrl 

Logs: This EPID group ID Successful 
```



#### 5. Request to create Quote for report

App 侧取到  report 创建 QE enclave 生成 Quote。对 QE enclave 进行本地认证并判断 QE enclave 是否为同一平台，如果错误终止执行。

```
Logs: Use enclave target info entering ocall_sgx_init_quote

Logs: Entering ocall_get_quote 

Logs: quote size = 1116 

Logs: Quote creation success 

Logs: rsgx_verify_report passed! 

Logs: qe_report check passed! 

Logs: Quote data => 
[2, 0, 0, 0, 75, 12, 0, 0, 13, 0, 13, 0, 0, 0, 0, 0, 47, 70, 72, 249, 110, 244, 249, 205, 67, 61, 27, 141, 184, 195, 62, 56, 211, 54, 10, 27, 157, 40, 205, 25, 55, 220, 230, 143, 94, 96, 217, 254, 19, 19, 2, 7, 255, 128, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 122, 8, 203, 143, 100, 209, 29, 192, 49, 220, 137, 22, 133, 230, 66, 194, 204, 30, 251, 136, 148, 34, 197, 54, 197, 103, 170, 9, 53, 82, 204, 154, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 131, 215, 25, 231, 125, 234, 202, 20, 112, 246, 186, 246, 42, 77, 119, 67, 3, 200, 153, 219, 105, 2, 15, 156, 112, 238, 29, 252, 8, 199, 206, 158, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 226, 137, 82, 68, 3, 107, 67, 67, 54, 179, 61, 194, 203, 220, 162, 136, 189, 121, 245, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 168, 2, 0, 0, 93, 44, 40, 153, 226, 98, 112, 165, 97, 177, 40, 147, 75, 34, 53, 208, 15, 249, 149, 176, 117, 208, 19, 4, 168, 189, 117, 86, 226, 81, 208, 126, 137, 245, 223, 65, 33, 145, 168, 84, 150, 223, 124, 35, 222, 69, 166, 169, 217, 9, 42, 84, 27, 165, 122, 78, 162, 199, 50, 155, 235, 9, 48, 248, 121, 80, 89, 101, 210, 84, 238, 81, 189, 216, 53, 136, 53, 63, 250, 135, 204, 228, 193, 193, 110, 27, 47, 173, 132, 68, 231, 52, 120, 4, 244, 170, 147, 194, 14, 40, 188, 24, 142, 141, 81, 85, 32, 157, 25, 183, 239, 252, 153, 46, 28, 208, 145, 186, 76, 106, 208, 169, 46, 43, 177, 184, 94, 33, 22, 234, 100, 208, 130, 119, 180, 91, 212, 8, 0, 165, 92, 192, 234, 163, 201, 14, 112, 65, 107, 38, 93, 232, 203, 206, 163, 119, 72, 151, 88, 138, 202, 192, 250, 200, 163, 87, 96, 153, 233, 243, 184, 40, 22, 134, 181, 80, 239, 128, 251, 225, 57, 176, 128, 67, 237, 88, 152, 206, 41, 183, 252, 158, 17, 37, 12, 198, 99, 158, 226, 25, 53, 167, 104, 163, 247, 235, 15, 91, 119, 193, 117, 224, 99, 220, 88, 4, 131, 241, 10, 207, 167, 136, 15, 150, 128, 163, 194, 230, 213, 153, 59, 171, 110, 66, 55, 129, 114, 205, 134, 115, 86, 45, 19, 193, 54, 206, 207, 137, 87, 43, 238, 222, 50, 48, 95, 72, 243, 78, 176, 111, 15, 179, 10, 44, 145, 98, 180, 133, 159, 175, 180, 19, 59, 187, 53, 157, 217, 154, 141, 157, 173, 17, 108, 63, 60, 156, 83, 212, 213, 123, 109, 181, 209, 58, 148, 95, 148, 183, 151, 146, 104, 1, 0, 0, 35, 48, 198, 133, 122, 62, 208, 212, 213, 116, 202, 233, 198, 64, 127, 21, 99, 134, 230, 249, 100, 6, 125, 211, 184, 207, 190, 91, 243, 151, 61, 183, 215, 105, 148, 101, 118, 128, 42, 223, 21, 209, 97, 21, 1, 194, 208, 37, 33, 50, 40, 232, 110, 51, 24, 170, 252, 5, 84, 129, 227, 86, 106, 15, 12, 53, 222, 68, 166, 41, 249, 148, 83, 91, 167, 137, 124, 171, 34, 36, 188, 23, 117, 24, 170, 58, 160, 82, 237, 34, 50, 133, 121, 66, 94, 229, 21, 86, 97, 139, 69, 215, 136, 51, 12, 4, 26, 26, 214, 98, 112, 220, 2, 137, 163, 86, 132, 144, 228, 203, 23, 150, 137, 158, 3, 101, 232, 123, 14, 176, 190, 199, 68, 59, 219, 139, 204, 67, 0, 169, 242, 68, 116, 52, 173, 204, 70, 52, 189, 221, 31, 195, 71, 236, 201, 123, 232, 48, 127, 76, 183, 90, 72, 14, 250, 89, 52, 2, 117, 136, 84, 238, 17, 100, 130, 145, 238, 192, 44, 8, 107, 207, 192, 136, 50, 22, 59, 76, 165, 94, 221, 179, 194, 47, 47, 123, 68, 70, 66, 121, 212, 176, 125, 183, 163, 183, 59, 176, 164, 226, 143, 122, 38, 44, 64, 216, 105, 180, 9, 171, 3, 40, 87, 106, 44, 115, 164, 177, 166, 181, 210, 24, 133, 237, 45, 192, 87, 34, 14, 22, 92, 218, 89, 251, 148, 33, 0, 172, 175, 242, 198, 6, 13, 68, 139, 151, 175, 11, 141, 5, 231, 26, 92, 171, 246, 47, 203, 89, 5, 216, 193, 251, 146, 94, 146, 20, 161, 243, 96, 20, 112, 42, 105, 79, 7, 108, 146, 71, 69, 40, 161, 234, 222, 5, 33, 232, 70, 36, 70, 216, 18, 154, 162, 5, 130, 15, 23, 215, 98, 87, 23, 4, 202, 244, 113, 108, 172, 189, 169, 204, 15, 5, 187, 250, 93, 152, 68, 91, 240, 29, 78, 144, 209, 208, 173, 150, 130, 75, 171, 58, 30, 0, 3, 102, 237, 139, 251, 162, 145, 187, 34, 84, 219, 34, 149, 116, 254, 29, 83, 51, 236, 165, 141, 214, 25, 79, 113, 222, 143, 211, 21, 5, 28, 28, 100, 201]
```



#### 6. Retuen Quote generated by QE

QE enclave 返回给 App 可进行 remote attestation 的 quote。

```
pub struct sgx_quote_t {
        pub version: uint16_t,                    /* 0   */
        pub sign_type: uint16_t,                  /* 2   */
        pub epid_group_id: sgx_epid_group_id_t,   /* 4   */
        pub qe_svn: sgx_isv_svn_t,                /* 8   */
        pub pce_svn: sgx_isv_svn_t,               /* 10  */
        pub xeid: uint32_t,                       /* 12  */
        pub basename: sgx_basename_t,             /* 16  */
        pub report_body: sgx_report_body_t,       /* 48  */
        pub signature_len: uint32_t,              /* 432 */
        pub signature: [uint8_t; 0],              /* 436 */
}
```



#### 7. Send Quote to IAS

调用 Intel 远程认证接口

```
Logs: Start verify quote from intel ias server 

Logs: Generate quote to json 

POST /sgx/dev/attestation/v3/report HTTP/1.1
HOST: api.trustedservices.intel.com
Ocp-Apim-Subscription-Key:19f4076a892e4a9683288e8c824eeaf2
Content-Length:1512
Content-Type: application/json
Connection: close

{"isvEnclaveQuote":"AgAAAEsMAAANAA0AAAAAAC9GSPlu9PnNQz0bjbjDPjjTNgobnSjNGTfc5o9eYNn+ExMCB/+ABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAHoIy49k0R3AMdyJFoXmQsLMHvuIlCLFNsVnqgk1UsyaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADA4olSRANrQ0M2sz3Cy9yiiL159QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAqAIAAF0sKJniYnClYbEok0siNdAP+ZWwddATBKi9dVbiUdB+ifXfQSGRqFSW33wj3kWmqdkJKlQbpXpOoscym+sJMPh5UFll0lTuUb3YNYg1P/qHzOTBwW4bL62EROc0eAT0qpPCDii8GI6NUVUgnRm37/yZLhzQkbpMatCpLiuxuF4hFupk0IJ3tFvUCAClXMDqo8kOcEFrJl3oy86jd0iXWIrKwPrIo1dgmenzuCgWhrVQ74D74TmwgEPtWJjOKbf8nhElDMZjnuIZNadoo/frD1t3wXXgY9xYBIPxCs+niA+WgKPC5tWZO6tuQjeBcs2Gc1YtE8E2zs+JVyvu3jIwX0jzTrBvD7MKLJFitIWfr7QTO7s1ndmajZ2tEWw/PJxT1NV7bbXROpRflLeXkmgBAAAjMMaFej7Q1NV0yunGQH8VY4bm+WQGfdO4z75b85c9t9dplGV2gCrfFdFhFQHC0CUhMijobjMYqvwFVIHjVmoPDDXeRKYp+ZRTW6eJfKsiJLwXdRiqOqBS7SIyhXlCXuUVVmGLRdeIMwwEGhrWYnDcAomjVoSQ5MsXlomeA2Xoew6wvsdEO9uLzEMAqfJEdDStzEY0vd0fw0fsyXvoMH9Mt1pIDvpZNAJ1iFTuEWSCke7ALAhrz8CIMhY7TKVe3bPCLy97REZCedSwfbejtzuwpOKPeiYsQNhptAmrAyhXaixzpLGmtdIYhe0twFciDhZc2ln7lCEArK/yxgYNRIuXrwuNBecaXKv2L8tZBdjB+5JekhSh82AUcCppTwdskkdFKKHq3gUh6EYkRtgSmqIFgg8X12JXFwTK9HFsrL2pzA8Fu/pdmERb8B1OkNHQrZaCS6s6HgADZu2L+6KRuyJU2yKVdP4dUzPspY3WGU9x3o/TFQUcHGTJ"}

Logs: Parse response attn report 

Attestation report: {"id":"38046799451932324826876584204846142652","timestamp":"2022-11-28T14:12:11.247396","version":3,"isvEnclaveQuoteStatus":"OK","isvEnclaveQuoteBody":"AgAAAEsMAAANAA0AAAAAAC9GSPlu9PnNQz0bjbjDPjjTNgobnSjNGTfc5o9eYNn+ExMCB/+ABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAHoIy49k0R3AMdyJFoXmQsLMHvuIlCLFNsVnqgk1UsyaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADA4olSRANrQ0M2sz3Cy9yiiL159QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
ECALL success!
```



#### 8. Parser attestation verification report

```
Logs: sgx quote version = 2
Logs: sgx quote signature type = 0
Logs: sgx quote report_data = [192, 226, 137, 82, 68, 3, 107, 67, 67, 54, 179, 61, 194, 203, 220, 162, 136, 189, 121, 245, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
Logs: sgx quote mr_enclave = [130, 111, 63, 26, 217, 248, 120, 84, 238, 160, 132, 200, 9, 214, 253, 82, 180, 168, 128, 108, 19, 255, 216, 249, 135, 94, 247, 220, 179, 22, 146, 86]
Logs: sgx quote mr_signer = [131, 215, 25, 231, 125, 234, 202, 20, 112, 246, 186, 246, 42, 77, 119, 67, 3, 200, 153, 219, 105, 2, 15, 156, 112, 238, 29, 252, 8, 199, 206, 158]
```





### Logs

```

[+] Init Enclave Successful 2!
Logs: App Running, This is normal world Rust Sting 

Logs: This is a in-Enclave Rust string! 

Logs: Has been created enclave key, now read! 

Logs: Get enclave public key! 

EnclavePublicKey(PublicKey(Affine { x: Field { n: [80807, 19696501, 1781662, 23077581, 45415550, 39153554, 41941805, 5207957, 40693373, 823325], magnitude: 1, normalized: false }, y: Field { n: [31617144, 4544564, 42533665, 27772383, 19643801, 50745896, 31307533, 54110940, 27384169, 770119], magnitude: 1, normalized: false }, infinity: false })) 

Bytes: [2, 50, 64, 118, 108, 238, 125, 19, 221, 229, 103, 255, 178, 217, 85, 190, 74, 180, 252, 126, 88, 8, 179, 65, 178, 249, 228, 178, 45, 212, 1, 59, 167] 

Logs: Sign some things msg! 

Ok([185, 183, 60, 100, 51, 62, 177, 76, 206, 17, 237, 1, 181, 52, 97, 79, 221, 169, 165, 70, 112, 214, 105, 144, 120, 214, 142, 253, 130, 54, 82, 105, 120, 100, 55, 36, 145, 189, 47, 146, 20, 75, 226, 48, 174, 119, 252, 115, 255, 68, 36, 78, 66, 63, 106, 32, 42, 196, 196, 65, 210, 58, 213, 4, 0])  

Logs: Verify sign msg! 

Ok(())  

Logs: Generate sgx report body is include enclave public key! 

Logs: Generate enclave target info 

Logs: Use enclave target info entering ocall_sgx_init_quote 

Log: Use enclave target info generat report creation success, This report mr_signer = [131, 215, 25, 231, 125, 234, 202, 20, 112, 246, 186, 246, 42, 77, 119, 67, 3, 200, 153, 219, 105, 2, 15, 156, 112, 238, 29, 252, 8, 199, 206, 158] 
 
Logs: Get sigrl from intel 

Logs: Local eg = [75, 12, 0, 0] 

GET /sgx/dev/attestation/v3/sigrl/00000c4b HTTP/1.1
HOST: api.trustedservices.intel.com
Ocp-Apim-Subscription-Key: 19f4076a892e4a9683288e8c824eeaf2
Connection: Close


Logs: Parse response sigrl 

Logs: This EPID group ID Successful 

Logs: Entering ocall_get_quote 

Logs: quote size = 1116 

Logs: Quote creation success 

Logs: rsgx_verify_report passed! 

Logs: qe_report check passed! 

Logs: Quote data => 
[2, 0, 0, 0, 75, 12, 0, 0, 13, 0, 13, 0, 0, 0, 0, 0, 47, 70, 72, 249, 110, 244, 249, 205, 67, 61, 27, 141, 184, 195, 62, 56, 181, 186, 137, 81, 159, 107, 26, 232, 114, 219, 222, 16, 110, 27, 95, 95, 19, 19, 2, 7, 255, 128, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 130, 111, 63, 26, 217, 248, 120, 84, 238, 160, 132, 200, 9, 214, 253, 82, 180, 168, 128, 108, 19, 255, 216, 249, 135, 94, 247, 220, 179, 22, 146, 86, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 131, 215, 25, 231, 125, 234, 202, 20, 112, 246, 186, 246, 42, 77, 119, 67, 3, 200, 153, 219, 105, 2, 15, 156, 112, 238, 29, 252, 8, 199, 206, 158, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 226, 137, 82, 68, 3, 107, 67, 67, 54, 179, 61, 194, 203, 220, 162, 136, 189, 121, 245, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 168, 2, 0, 0, 47, 147, 14, 193, 29, 47, 30, 146, 44, 231, 14, 219, 79, 118, 58, 84, 105, 35, 58, 222, 255, 220, 210, 72, 97, 175, 243, 35, 45, 123, 216, 199, 100, 149, 228, 95, 204, 89, 221, 154, 30, 141, 7, 14, 209, 156, 92, 162, 123, 152, 114, 229, 22, 21, 97, 49, 14, 73, 82, 28, 118, 18, 24, 83, 119, 187, 113, 26, 33, 109, 252, 239, 197, 156, 211, 176, 119, 221, 123, 73, 108, 91, 163, 143, 113, 108, 143, 193, 235, 71, 143, 96, 105, 133, 251, 52, 186, 192, 73, 200, 230, 122, 223, 68, 57, 49, 118, 164, 94, 206, 196, 251, 233, 54, 101, 62, 82, 212, 103, 195, 93, 14, 63, 211, 150, 82, 126, 151, 194, 175, 135, 102, 137, 220, 175, 108, 49, 209, 84, 98, 65, 132, 171, 240, 144, 100, 207, 80, 150, 161, 99, 235, 137, 24, 255, 176, 179, 158, 239, 157, 87, 122, 171, 36, 142, 253, 194, 220, 139, 181, 182, 7, 248, 188, 7, 209, 119, 35, 11, 197, 142, 127, 111, 109, 52, 172, 245, 110, 235, 130, 240, 189, 151, 185, 2, 169, 219, 9, 139, 51, 157, 236, 53, 112, 107, 252, 112, 154, 154, 118, 20, 135, 57, 165, 90, 238, 174, 191, 13, 142, 85, 66, 130, 210, 103, 43, 39, 242, 148, 165, 71, 160, 151, 227, 102, 169, 64, 1, 178, 64, 72, 187, 166, 223, 166, 121, 182, 17, 46, 115, 25, 163, 37, 100, 21, 159, 12, 129, 225, 162, 159, 252, 2, 86, 20, 42, 76, 226, 109, 194, 192, 155, 192, 167, 213, 249, 155, 69, 157, 18, 24, 133, 13, 15, 164, 242, 41, 252, 188, 25, 10, 117, 20, 149, 52, 36, 141, 76, 231, 17, 104, 1, 0, 0, 117, 37, 7, 118, 101, 49, 210, 135, 188, 219, 247, 228, 28, 200, 139, 102, 177, 242, 196, 39, 210, 8, 179, 181, 100, 227, 32, 151, 150, 174, 3, 230, 179, 200, 138, 116, 210, 76, 121, 83, 174, 190, 0, 207, 180, 242, 1, 142, 168, 169, 115, 145, 211, 46, 138, 245, 143, 39, 94, 1, 24, 65, 77, 214, 212, 217, 74, 173, 89, 114, 242, 189, 188, 67, 8, 107, 126, 232, 152, 90, 200, 147, 144, 198, 16, 209, 232, 4, 141, 44, 241, 171, 218, 27, 171, 195, 78, 178, 61, 232, 36, 252, 145, 91, 67, 73, 175, 219, 116, 165, 14, 9, 13, 147, 177, 2, 236, 126, 173, 184, 58, 129, 226, 238, 252, 27, 190, 80, 237, 76, 82, 155, 245, 65, 229, 22, 80, 159, 242, 103, 251, 175, 110, 225, 87, 48, 96, 81, 55, 140, 103, 125, 69, 197, 36, 254, 232, 219, 226, 159, 34, 132, 251, 122, 95, 158, 78, 47, 180, 81, 59, 255, 225, 53, 54, 152, 160, 63, 97, 84, 239, 185, 202, 220, 182, 81, 210, 232, 63, 33, 213, 239, 189, 239, 95, 197, 71, 212, 75, 4, 4, 225, 13, 177, 236, 174, 68, 135, 3, 219, 90, 112, 122, 212, 219, 43, 34, 140, 46, 242, 145, 161, 208, 154, 191, 253, 25, 115, 180, 20, 182, 23, 246, 119, 144, 51, 8, 122, 138, 44, 67, 91, 211, 48, 48, 106, 152, 21, 147, 104, 212, 103, 84, 68, 21, 53, 57, 198, 47, 149, 167, 89, 222, 173, 209, 16, 8, 49, 135, 54, 172, 222, 129, 170, 35, 154, 239, 28, 164, 11, 196, 78, 163, 254, 199, 162, 241, 213, 68, 221, 16, 172, 182, 57, 251, 106, 137, 90, 99, 58, 12, 51, 229, 84, 17, 96, 19, 68, 27, 26, 240, 41, 12, 34, 22, 13, 24, 56, 80, 217, 171, 121, 205, 189, 44, 43, 40, 1, 41, 75, 220, 212, 222, 182, 147, 220, 246, 49, 10, 137, 41, 127, 43, 78, 86, 182, 176, 120, 70, 228, 175, 78, 188, 20, 214, 57, 58, 40, 37, 120, 2, 178, 55, 16, 252, 79, 54, 48, 65, 107, 115, 185, 214, 222, 38, 103]

Logs: Start verify quote from intel ias server 

Logs: Generate quote to json 

POST /sgx/dev/attestation/v3/report HTTP/1.1
HOST: api.trustedservices.intel.com
Ocp-Apim-Subscription-Key:19f4076a892e4a9683288e8c824eeaf2
Content-Length:1512
Content-Type: application/json
Connection: close

{"isvEnclaveQuote":"AgAAAEsMAAANAA0AAAAAAC9GSPlu9PnNQz0bjbjDPji1uolRn2sa6HLb3hBuG19fExMCB/+ABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAIJvPxrZ+HhU7qCEyAnW/VK0qIBsE//Y+Yde99yzFpJWAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADA4olSRANrQ0M2sz3Cy9yiiL159QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAqAIAAC+TDsEdLx6SLOcO2092OlRpIzre/9zSSGGv8yMte9jHZJXkX8xZ3ZoejQcO0ZxconuYcuUWFWExDklSHHYSGFN3u3EaIW3878Wc07B33XtJbFujj3Fsj8HrR49gaYX7NLrAScjmet9EOTF2pF7OxPvpNmU+UtRnw10OP9OWUn6Xwq+HZoncr2wx0VRiQYSr8JBkz1CWoWPriRj/sLOe751Xeqskjv3C3Iu1tgf4vAfRdyMLxY5/b200rPVu64LwvZe5AqnbCYsznew1cGv8cJqadhSHOaVa7q6/DY5VQoLSZysn8pSlR6CX42apQAGyQEi7pt+mebYRLnMZoyVkFZ8MgeGin/wCVhQqTOJtwsCbwKfV+ZtFnRIYhQ0PpPIp/LwZCnUUlTQkjUznEWgBAAB1JQd2ZTHSh7zb9+QcyItmsfLEJ9IIs7Vk4yCXlq4D5rPIinTSTHlTrr4Az7TyAY6oqXOR0y6K9Y8nXgEYQU3W1NlKrVly8r28QwhrfuiYWsiTkMYQ0egEjSzxq9obq8NOsj3oJPyRW0NJr9t0pQ4JDZOxAux+rbg6geLu/Bu+UO1MUpv1QeUWUJ/yZ/uvbuFXMGBRN4xnfUXFJP7o2+KfIoT7el+eTi+0UTv/4TU2mKA/YVTvucrctlHS6D8h1e+971/FR9RLBAThDbHsrkSHA9tacHrU2ysijC7ykaHQmr/9GXO0FLYX9neQMwh6iixDW9MwMGqYFZNo1GdURBU1OcYvladZ3q3REAgxhzas3oGqI5rvHKQLxE6j/sei8dVE3RCstjn7aolaYzoMM+VUEWATRBsa8CkMIhYNGDhQ2at5zb0sKygBKUvc1N62k9z2MQqJKX8rTla2sHhG5K9OvBTWOTooJXgCsjcQ/E82MEFrc7nW3iZn"}

Logs: Parse response attn report 

Logs: Attestation report: {"id":"260927756302291035456995209117016821230","timestamp":"2022-11-28T15:37:43.769355","version":3,"isvEnclaveQuoteStatus":"OK","isvEnclaveQuoteBody":"AgAAAEsMAAANAA0AAAAAAC9GSPlu9PnNQz0bjbjDPji1uolRn2sa6HLb3hBuG19fExMCB/+ABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAIJvPxrZ+HhU7qCEyAnW/VK0qIBsE//Y+Yde99yzFpJWAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADA4olSRANrQ0M2sz3Cy9yiiL159QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"} 

Logs: sgx quote version = 2
Logs: sgx quote signature type = 0
Logs: sgx quote report_data = [192, 226, 137, 82, 68, 3, 107, 67, 67, 54, 179, 61, 194, 203, 220, 162, 136, 189, 121, 245, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
Logs: sgx quote mr_enclave = [130, 111, 63, 26, 217, 248, 120, 84, 238, 160, 132, 200, 9, 214, 253, 82, 180, 168, 128, 108, 19, 255, 216, 249, 135, 94, 247, 220, 179, 22, 146, 86]
Logs: sgx quote mr_signer = [131, 215, 25, 231, 125, 234, 202, 20, 112, 246, 186, 246, 42, 77, 119, 67, 3, 200, 153, 219, 105, 2, 15, 156, 112, 238, 29, 252, 8, 199, 206, 158]
ECALL success!
[+] Done!
```

