## 总览
![](https://docs.lcp.network/assets/images/remote-attestation-5b648793abb56c1bcb64d02828771ad2.png)

## Remote Attestation
远程认证的过程中, 假设远程认证方 B 要认证 enclave A, A 先执行 EREPORT 指令, 将 A 的身份和附加信息组合生成 REPORT 结构, 取出本地密钥库版本调用 Intel 接口判断是否有已知安全风险。然后利用引用 enclave (称其为 Q) 的报告密钥生成一个 MAC, 连同报告结构一起发给 Q, Q 通过该结构验证 A 是否运行于同一平台, 然后将它封装为一个引用结构体 QUOTE, 并使用 EPID 进行签名, 将 QUOTE 发送给远程认证者.

远程认证者获取到 QUOTE 发送 QUOTE 到 Intel IAS, IAS 返回认证结果, 如果返回 OK, 则远程认证者解析 QUOTE 获取 REPORT 结构中的附加信息(此示例为公钥).

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

Hex: c0e2895244036b434336b33dc2cbdca288bd79f5 

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

把 Quote Base64 转换并调用 Intel 远程认证接口

```
Logs: Start verify quote from intel ias server 

Logs: Generate quote to json 

POST /sgx/dev/attestation/v3/report HTTP/1.1
HOST: api.trustedservices.intel.com
Ocp-Apim-Subscription-Key:19f4076a892e4a9683288e8c824eeaf2
Content-Length:1512
Content-Type: application/json
Connection: close

{
	"isvEnclaveQuote": "AgAAAEsMAAANAA0AAAAAAC9GSPlu9PnNQz0bjbjDPjjTNgobnSjNGTfc5o9eYNn+ExMCB/+ABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAHoIy49k0R3AMdyJFoXmQsLMHvuIlCLFNsVnqgk1UsyaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADA4olSRANrQ0M2sz3Cy9yiiL159QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAqAIAAF0sKJniYnClYbEok0siNdAP+ZWwddATBKi9dVbiUdB+ifXfQSGRqFSW33wj3kWmqdkJKlQbpXpOoscym+sJMPh5UFll0lTuUb3YNYg1P/qHzOTBwW4bL62EROc0eAT0qpPCDii8GI6NUVUgnRm37/yZLhzQkbpMatCpLiuxuF4hFupk0IJ3tFvUCAClXMDqo8kOcEFrJl3oy86jd0iXWIrKwPrIo1dgmenzuCgWhrVQ74D74TmwgEPtWJjOKbf8nhElDMZjnuIZNadoo/frD1t3wXXgY9xYBIPxCs+niA+WgKPC5tWZO6tuQjeBcs2Gc1YtE8E2zs+JVyvu3jIwX0jzTrBvD7MKLJFitIWfr7QTO7s1ndmajZ2tEWw/PJxT1NV7bbXROpRflLeXkmgBAAAjMMaFej7Q1NV0yunGQH8VY4bm+WQGfdO4z75b85c9t9dplGV2gCrfFdFhFQHC0CUhMijobjMYqvwFVIHjVmoPDDXeRKYp+ZRTW6eJfKsiJLwXdRiqOqBS7SIyhXlCXuUVVmGLRdeIMwwEGhrWYnDcAomjVoSQ5MsXlomeA2Xoew6wvsdEO9uLzEMAqfJEdDStzEY0vd0fw0fsyXvoMH9Mt1pIDvpZNAJ1iFTuEWSCke7ALAhrz8CIMhY7TKVe3bPCLy97REZCedSwfbejtzuwpOKPeiYsQNhptAmrAyhXaixzpLGmtdIYhe0twFciDhZc2ln7lCEArK/yxgYNRIuXrwuNBecaXKv2L8tZBdjB+5JekhSh82AUcCppTwdskkdFKKHq3gUh6EYkRtgSmqIFgg8X12JXFwTK9HFsrL2pzA8Fu/pdmERb8B1OkNHQrZaCS6s6HgADZu2L+6KRuyJU2yKVdP4dUzPspY3WGU9x3o/TFQUcHGTJ"
}

```

#### 8. Retuen the attestation verification report(AVR)

```
Logs: Parse response attn report 

Logs: Attestation report: 

{
	"id": "260927756302291035456995209117016821230",
	"timestamp": "2022-11-28T15:37:43.769355",
	"version": 3,
	"isvEnclaveQuoteStatus": "OK",
	"isvEnclaveQuoteBody": "AgAAAEsMAAANAA0AAAAAAC9GSPlu9PnNQz0bjbjDPji1uolRn2sa6HLb3hBuG19fExMCB/+ABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAIJvPxrZ+HhU7qCEyAnW/VK0qIBsE//Y+Yde99yzFpJWAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADA4olSRANrQ0M2sz3Cy9yiiL159QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
}

```



#### 9. Parser attestation verification report

解析经过认证的 Quote 结构, 取出自定义数据

```
Logs: sgx quote report_data public key hex "c0e2895244036b434336b33dc2cbdca288bd79f5"
Logs: sgx quote version = 2
Logs: sgx quote signature type = 0
Logs: sgx quote report_data = [192, 226, 137, 82, 68, 3, 107, 67, 67, 54, 179, 61, 194, 203, 220, 162, 136, 189, 121, 245, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
Logs: sgx quote mr_enclave = [130, 111, 63, 26, 217, 248, 120, 84, 238, 160, 132, 200, 9, 214, 253, 82, 180, 168, 128, 108, 19, 255, 216, 249, 135, 94, 247, 220, 179, 22, 146, 86]
Logs: sgx quote mr_signer = [131, 215, 25, 231, 125, 234, 202, 20, 112, 246, 186, 246, 42, 77, 119, 67, 3, 200, 153, 219, 105, 2, 15, 156, 112, 238, 29, 252, 8, 199, 206, 158]
```





### Logs

```
SIGN =>  bin/enclave.signed.so
[+] Init Enclave Successful 2!
Logs: App Running, This is normal world Rust Sting 

Logs: This is a in-Enclave Rust string! 

Logs: Has been created enclave key, now read! 

Logs: Get enclave public key! 

EnclavePublicKey(PublicKey(Affine { x: Field { n: [80807, 19696501, 1781662, 23077581, 45415550, 39153554, 41941805, 5207957, 40693373, 823325], magnitude: 1, normalized: false }, y: Field { n: [31617144, 4544564, 42533665, 27772383, 19643801, 50745896, 31307533, 54110940, 27384169, 770119], magnitude: 1, normalized: false }, infinity: false })) 

Bytes: [2, 50, 64, 118, 108, 238, 125, 19, 221, 229, 103, 255, 178, 217, 85, 190, 74, 180, 252, 126, 88, 8, 179, 65, 178, 249, 228, 178, 45, 212, 1, 59, 167] 

Hex: c0e2895244036b434336b33dc2cbdca288bd79f5 

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
[2, 0, 0, 0, 75, 12, 0, 0, 13, 0, 13, 0, 0, 0, 0, 0, 47, 70, 72, 249, 110, 244, 249, 205, 67, 61, 27, 141, 184, 195, 62, 56, 161, 77, 11, 250, 27, 77, 125, 188, 102, 242, 87, 185, 232, 105, 234, 127, 19, 19, 2, 7, 255, 128, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 127, 14, 101, 226, 134, 49, 43, 99, 54, 174, 33, 191, 187, 236, 16, 212, 72, 83, 67, 18, 76, 124, 150, 142, 233, 205, 135, 158, 34, 209, 12, 161, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 131, 215, 25, 231, 125, 234, 202, 20, 112, 246, 186, 246, 42, 77, 119, 67, 3, 200, 153, 219, 105, 2, 15, 156, 112, 238, 29, 252, 8, 199, 206, 158, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 226, 137, 82, 68, 3, 107, 67, 67, 54, 179, 61, 194, 203, 220, 162, 136, 189, 121, 245, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 168, 2, 0, 0, 21, 201, 176, 124, 179, 94, 50, 202, 7, 25, 174, 148, 181, 234, 200, 47, 56, 187, 215, 189, 47, 113, 19, 170, 75, 62, 236, 227, 150, 109, 249, 134, 21, 249, 146, 218, 189, 119, 189, 236, 35, 42, 34, 142, 133, 39, 64, 198, 84, 171, 37, 118, 235, 252, 2, 237, 191, 37, 201, 30, 89, 146, 40, 125, 175, 208, 26, 32, 15, 67, 24, 84, 191, 139, 126, 57, 145, 231, 142, 215, 42, 7, 183, 28, 23, 81, 41, 150, 241, 252, 223, 242, 75, 14, 244, 149, 139, 214, 24, 16, 133, 131, 254, 180, 31, 84, 79, 213, 182, 207, 176, 167, 118, 38, 123, 222, 31, 223, 87, 135, 155, 127, 187, 18, 143, 187, 151, 200, 9, 56, 18, 54, 57, 240, 123, 131, 55, 216, 165, 209, 111, 130, 147, 233, 143, 203, 119, 57, 223, 111, 105, 214, 107, 109, 0, 1, 200, 147, 244, 219, 162, 193, 64, 182, 86, 34, 239, 174, 80, 212, 57, 62, 87, 245, 227, 226, 212, 62, 251, 71, 175, 175, 185, 226, 196, 54, 225, 192, 138, 104, 103, 125, 245, 100, 235, 205, 66, 79, 148, 176, 27, 213, 26, 69, 243, 4, 124, 175, 145, 101, 138, 107, 0, 177, 160, 6, 137, 45, 40, 254, 155, 143, 116, 255, 183, 41, 99, 153, 142, 237, 250, 113, 45, 144, 117, 167, 163, 100, 225, 138, 183, 118, 79, 34, 162, 203, 141, 21, 53, 229, 4, 116, 253, 7, 56, 115, 246, 85, 174, 230, 115, 251, 56, 20, 176, 6, 155, 34, 248, 112, 168, 233, 7, 101, 15, 126, 62, 8, 194, 68, 147, 47, 34, 176, 33, 47, 217, 43, 224, 242, 249, 179, 139, 228, 179, 200, 237, 26, 7, 225, 104, 1, 0, 0, 228, 201, 119, 132, 24, 69, 150, 149, 16, 44, 244, 244, 71, 201, 55, 142, 9, 105, 197, 64, 229, 35, 38, 183, 77, 191, 170, 67, 90, 230, 188, 43, 47, 155, 204, 109, 173, 195, 126, 122, 119, 44, 0, 72, 129, 52, 123, 5, 33, 180, 207, 71, 124, 86, 225, 9, 217, 220, 219, 154, 144, 165, 159, 103, 36, 34, 157, 192, 220, 121, 210, 42, 178, 154, 161, 175, 35, 247, 232, 166, 117, 147, 183, 167, 111, 252, 161, 112, 160, 178, 1, 32, 196, 56, 29, 125, 215, 175, 15, 16, 134, 241, 82, 154, 131, 61, 21, 100, 138, 80, 232, 121, 122, 8, 169, 122, 18, 241, 77, 192, 244, 103, 112, 137, 182, 130, 179, 253, 223, 12, 81, 91, 55, 205, 101, 227, 184, 19, 221, 104, 38, 149, 88, 150, 138, 254, 37, 154, 189, 65, 248, 248, 182, 137, 195, 4, 140, 216, 173, 58, 67, 130, 247, 140, 204, 113, 62, 177, 214, 71, 204, 149, 69, 44, 93, 35, 182, 160, 104, 135, 54, 225, 151, 177, 205, 28, 112, 46, 26, 169, 110, 187, 238, 164, 249, 130, 167, 91, 29, 4, 136, 190, 40, 93, 24, 132, 161, 26, 236, 206, 23, 249, 255, 176, 136, 97, 216, 156, 185, 186, 74, 101, 162, 237, 7, 123, 85, 147, 21, 68, 73, 25, 7, 216, 245, 126, 243, 186, 72, 207, 192, 57, 223, 123, 208, 251, 134, 134, 15, 3, 209, 58, 152, 219, 227, 101, 169, 122, 95, 218, 77, 198, 83, 200, 133, 6, 80, 123, 214, 161, 175, 86, 62, 90, 37, 106, 154, 105, 133, 136, 132, 89, 116, 40, 178, 20, 12, 251, 240, 7, 227, 242, 114, 133, 175, 129, 164, 114, 72, 116, 106, 11, 20, 162, 12, 115, 237, 105, 33, 64, 118, 199, 163, 195, 37, 118, 139, 46, 209, 98, 32, 186, 180, 220, 14, 146, 115, 159, 135, 79, 81, 22, 167, 205, 247, 133, 232, 245, 146, 249, 93, 12, 28, 252, 5, 237, 227, 133, 254, 131, 201, 153, 69, 238, 234, 195, 128, 56, 48, 22, 231, 26, 53, 154, 253, 111, 128, 53, 136, 202, 31, 106, 195, 142, 228, 120]

Logs: Start verify quote from intel ias server 

Logs: Generate quote to json 

POST /sgx/dev/attestation/v3/report HTTP/1.1
HOST: api.trustedservices.intel.com
Ocp-Apim-Subscription-Key:19f4076a892e4a9683288e8c824eeaf2
Content-Length:1512
Content-Type: application/json
Connection: close

{"isvEnclaveQuote":"AgAAAEsMAAANAA0AAAAAAC9GSPlu9PnNQz0bjbjDPjihTQv6G019vGbyV7noaep/ExMCB/+ABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAH8OZeKGMStjNq4hv7vsENRIU0MSTHyWjunNh54i0QyhAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADA4olSRANrQ0M2sz3Cy9yiiL159QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAqAIAABXJsHyzXjLKBxmulLXqyC84u9e9L3ETqks+7OOWbfmGFfmS2r13vewjKiKOhSdAxlSrJXbr/ALtvyXJHlmSKH2v0BogD0MYVL+LfjmR547XKge3HBdRKZbx/N/ySw70lYvWGBCFg/60H1RP1bbPsKd2JnveH99Xh5t/uxKPu5fICTgSNjnwe4M32KXRb4KT6Y/Ldznfb2nWa20AAciT9NuiwUC2ViLvrlDUOT5X9ePi1D77R6+vueLENuHAimhnffVk681CT5SwG9UaRfMEfK+RZYprALGgBoktKP6bj3T/tyljmY7t+nEtkHWno2Third2TyKiy40VNeUEdP0HOHP2Va7mc/s4FLAGmyL4cKjpB2UPfj4IwkSTLyKwIS/ZK+Dy+bOL5LPI7RoH4WgBAADkyXeEGEWWlRAs9PRHyTeOCWnFQOUjJrdNv6pDWua8Ky+bzG2tw356dywASIE0ewUhtM9HfFbhCdnc25qQpZ9nJCKdwNx50iqymqGvI/fopnWTt6dv/KFwoLIBIMQ4HX3Xrw8QhvFSmoM9FWSKUOh5egipehLxTcD0Z3CJtoKz/d8MUVs3zWXjuBPdaCaVWJaK/iWavUH4+LaJwwSM2K06Q4L3jMxxPrHWR8yVRSxdI7agaIc24ZexzRxwLhqpbrvupPmCp1sdBIi+KF0YhKEa7M4X+f+wiGHYnLm6SmWi7Qd7VZMVREkZB9j1fvO6SM/AOd970PuGhg8D0TqY2+NlqXpf2k3GU8iFBlB71qGvVj5aJWqaaYWIhFl0KLIUDPvwB+PycoWvgaRySHRqCxSiDHPtaSFAdsejwyV2iy7RYiC6tNwOknOfh09RFqfN94Xo9ZL5XQwc/AXt44X+g8mZRe7qw4A4MBbnGjWa/W+ANYjKH2rDjuR4"}

Logs: Parse response attn report 

Logs: Attestation report: {"id":"72721086962888351808347254557217892187","timestamp":"2022-11-28T16:37:22.125473","version":3,"isvEnclaveQuoteStatus":"OK","isvEnclaveQuoteBody":"AgAAAEsMAAANAA0AAAAAAC9GSPlu9PnNQz0bjbjDPjihTQv6G019vGbyV7noaep/ExMCB/+ABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAH8OZeKGMStjNq4hv7vsENRIU0MSTHyWjunNh54i0QyhAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADA4olSRANrQ0M2sz3Cy9yiiL159QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"} 

Logs: sgx quote report_data public key hex "c0e2895244036b434336b33dc2cbdca288bd79f5"
Logs: sgx quote version = 2
Logs: sgx quote signature type = 0
Logs: sgx quote report_data = [192, 226, 137, 82, 68, 3, 107, 67, 67, 54, 179, 61, 194, 203, 220, 162, 136, 189, 121, 245, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
Logs: sgx quote mr_enclave = [127, 14, 101, 226, 134, 49, 43, 99, 54, 174, 33, 191, 187, 236, 16, 212, 72, 83, 67, 18, 76, 124, 150, 142, 233, 205, 135, 158, 34, 209, 12, 161]
Logs: sgx quote mr_signer = [131, 215, 25, 231, 125, 234, 202, 20, 112, 246, 186, 246, 42, 77, 119, 67, 3, 200, 153, 219, 105, 2, 15, 156, 112, 238, 29, 252, 8, 199, 206, 158]
ECALL success!
[+] Done!
```

