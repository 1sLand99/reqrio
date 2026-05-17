# reqrio export function

* char **一般是错误，传入一个nullptr。函数调用后应检查其是否为nullptr，若为nullptr应获取对应的错误，并使用char_free对其进行内存释放
* 返回char *, 与char **基本一致

## ScReq

请求类及其方法

| No. | Function              | Params                                  | Res        |
|:---:|:----------------------|:----------------------------------------|:-----------|
|  1  | ScReq_new             | -                                       | ScReq *    |
|  2  | ScReq_set_header_json | ScReq *, const char *                   | char *     |
|  3  | ScReq_add_header      | ScReq *, const char *, const char *     | char *     |
|  4  | ScReq_remove_header   | ScReq *, const char *                   | char *     |
|  5  | ScReq_set_alpn        | ScReq *, const char *                   | char *     |
|  6  | ScReq_set_verify      | ScReq *, bool                           | char *     |
|  7  | ScReq_set_redirect    | ScReq *, bool                           | char *     |
|  8  | ScReq_set_key_log     | ScReq *, const char *                   | char *     |
|  9  | ScReq_set_fingerprint | ScReq *, void *                         | char *     |
| 10  | ScReq_set_proxy       | ScReq *, const char *                   | char *     |
| 11  | ScReq_set_timeout     | ScReq *, const char *                   | char *     |
| 12  | ScReq_set_cookie      | ScReq *, const char *                   | char *     |
| 13  | ScReq_add_cookie      | ScReq *, const char *, const char *     | char *     |
| 14  | ScReq_stream_io       | ScReq *, Method, Url *, Body *, char ** | Response * |
| 15  | ScReq_reconnect       | ScReq *                                 | char *     |
| 16  | ScReq_connect         | ScReq *                                 | char *     |
| 17  | ScReq_close_stream    | ScReq *                                 | char *     |
| 18  | ScReq_drop            | ScReq *                                 | -          |

### 请求方法类型

```c
enum Method {
    GET = 0,
    POST = 1,
    PUT = 2,
    HEAD = 3,
    DELETE = 4,
    OPTIONS = 5,
    TRACE = 6,
    CONNECT = 7,
    PATCH = 8,
}
```

## Url

请求的地址

| No. | Function         | Params                            | Res    |
|:---:|:-----------------|:----------------------------------|:-------|
|  1  | Url_new          | const char *, char **             | Url *  |
|  2  | Url_add_param    | Url *, const char *, const char * | char * |
|  3  | Url_remove_param | Url *, const char *               | char * |
|  4  | Url_set_sni      | Url *, const char *               | char * |
|  5  | Url_drop         | Url *                             | -      |

## Response

请求的响应体

| No. | Function             | Params                                  | Res       |
|:---:|:---------------------|:----------------------------------------|:----------|
|  1  | Response_status_code | const Response *, char **               | uint16_t  |
|  2  | Response_get_header  | const Response *, const char *, char ** | char *    |
|  3  | Response_cookies     | const Response *, char **               | char *    |
|  4  | Response_bytes       | Response *, size_t *, char **           | uint8_t * |
|  5  | Response_drop        | Response *                              | -         |

### TLS参数

#### CipherSuite

```c
enum CipherSuite {
    // ecdhe-ecdhe
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xc02b,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xc02c,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 0xc023,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = 0xc024,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0xc009,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0xc00a,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca9,

    // ecdhe-rsa
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xc02f,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xc030,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = 0xc027,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = 0xc028,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xc013,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xc014,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca8,

    // dhe-rsa
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = 0x009e,
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = 0x009f,
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = 0x0067,
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = 0x006b,
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA = 0x0033,
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA = 0x0039,
    TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xccaa,

    // rsa
    TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009c,
    TLS_RSA_WITH_AES_256_GCM_SHA384 = 0x009d,
    TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x003c,
    TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x003d,
    TLS_RSA_WITH_AES_128_CBC_SHA = 0x002f,
    TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035,

    // tls1.3
    TLS_AES_128_GCM_SHA256 = 0x1301,
    TLS_AES_256_GCM_SHA384 = 0x1302,
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303,

    TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00ff,
};
```

#### ExtensionType

```c
enum ExtensionType {
    ServerName = 0x0,
    StatusRequest = 0x5,
    SupportedGroup = 0xa,
    EcPointFormats = 0xb,
    SignatureAlgorithms = 0xd,
    ApplicationLayerProtocolNegotiation = 0x10,
    SignedCertificateTimestamp = 0x12,
    Padding = 0x15,
    EncryptTheMac = 0x16,
    ExtendMasterSecret = 0x17,
    SessionTicket = 0x23,
    CompressionCertificate = 0x1b,
    SupportedVersions = 0x2b,
    PskKeyExchangeMode = 0x2d,
    PostHandshakeAuth = 0x31,
    KeyShare = 0x33,
    RenegotiationInfo = 0xff01,
    EncryptedClientHello = 0xfe0d,
    ApplicationSetting = 0x44cd,
    PreSharedKey = 0x29,
    ApplicationSettingOld = 0x4469
};
```

#### SupportGroup

```c
enum SupportGroup {
    X25519 = 0x1d,
    X448 = 0x1e,
    X25519MLKEM768 = 0x11ec,
    Secp256r1 = 0x0017,
    Secp384r1 = 0x0018,
    Secp521r1 = 0x0019,
    FFDHE2048 = 0x0100,
    FFDHE3072 = 0x0101,
    FFDHE4096 = 0x0102,
    FFDHE6144 = 0x0103,
    FFDHE8192 = 0x0104,
};

```

#### Version

```c
enum Version {
    TLS_1_0 = 0x301,
    TLS_1_1 = 0x302,
    TLS_1_2 = 0x303,
    TLS_1_3 = 0x304
};
```

#### CompressionMethod

```c
enum CompressionMethod {
    NUL = 0,
    DEFLATE = 1,
    BROTLI = 2,
    GZIP = 0xFFFF,
    ZSTD = 0xFFFE
};
```

#### EcPointFormat

```c
enum EcPointFormat {
    UNCOMPRESSED = 0,
    ANSI_X962_PRIME = 1,
    ANSI_X962_CHAR2 = 2
};
```

## Fingerprint

Session指纹，包含TLS指纹和HTTP/2指纹

| No. | Function                       | Params                                              | Res           |
|:---:|:-------------------------------|:----------------------------------------------------|:--------------|
|  1  | Fingerprint_from_ja3           | const char *, const char *, char **                 | Fingerprint * |
|  2  | Fingerprint_from_ja4           | const char *, const char *, char **                 | Fingerprint * |
|  3  | Fingerprint_custom             | const char *, const char *token, char **            | Fingerprint * |
|  4  | Fingerprint_random             | const char *, char **                               | Fingerprint * |
|  5  | Fingerprint_from_client_hello  | const uint8_t *, size_t, const char *token, char ** | Fingerprint * |
|  6  | Fingerprint_new                | const char *                                        | Fingerprint * |
|  7  | Fingerprint_add_cipher_suite   | Fingerprint *, u16                                  | -             |
|  8  | Fingerprint_add_ext            | Fingerprint *, u16                                  | -             |
|  9  | Fingerprint_add_ext_alps       | Fingerprint *, u16, const char **, size_t           | -             |
| 10  | Fingerprint_add_ext_version    | Fingerprint *, u16, const uint16_t *, size_t        | -             |
| 11  | Fingerprint_add_ext_curve      | Fingerprint *, u16, const uint16_t *, size_t        | -             |
| 12  | Fingerprint_add_ext_psk_mode   | Fingerprint *, u16, u8                              | -             |
| 13  | Fingerprint_add_ext_padding    | Fingerprint *, u16, size_t                          | -             |
| 14  | Fingerprint_add_ext_bytes      | Fingerprint *, u16, const uint8_t *, size_t         | -             |
| 15  | Fingerprint_add_ext_algorithm  | Fingerprint *, u16, const uint16_t *, size_t        | -             |
| 16  | Fingerprint_add_ext_ec_point   | Fingerprint *, u16, const uint8_t *, size_t         | -             |
| 17  | Fingerprint_add_h2_setting     | Fingerprint *, u16, u32                             | -             |
| 18  | Fingerprint_set_h2_window_size | Fingerprint *, u32                                  | -             |
| 19  | Fingerprint_set_h2_priority    | Fingerprint *, bool, u8                             | -             |
| 20  | Fingerprint_drop               | Fingerprint *                                       | -             |

## Body

请求体

| No. | Function          | Params                                            | Res        |
|:---:|:------------------|:--------------------------------------------------|:-----------|
|  1  | Body_new          | const uint8_t *, size_t, const char *, char **    | Body *     |
|  2  | Body_none         | -                                                 | Body *     |
|  3  | Body_new_files    | HttpFile *, const char *, char **                 | Body *     |
|  4  | Body_drop         | Body *                                            | -          |
|  5  | HttpFile_new      | -                                                 | HttpFile * |
|  6  | HttpFile_add_form | HttpFile *, FileForm *                            | char *     |
|  7  | FileForm_new      | const char *, const char *, const char *, char ** | FileForm * |
|  8  | HttpFile_drop     | HttpFile *                                        | -          |

```c
enum CipherType {
    AES_128_CBC = 0,
    AES_192_CBC = 1,
    AES_256_CBC = 2,
    AES_128_ECB = 3,
    AES_192_ECB = 4,
    AES_256_ECB = 5,
    AES_128_CTR = 6,
    AES_192_CTR = 7,
    AES_256_CTR = 8,
    AES_128_GCM = 9,
    AES_192_GCM = 10,
    AES_256_GCM = 11,
    AES_128_OFB = 12,
    AES_192_OFB = 13,
    AES_256_OFB = 14,
    DES_CBC = 15,
    DES_ECB = 16,
    RC4 = 17,
}
```

```c
enum HashType {
    MD5 = 0,
    Sha1 = 1,
    Sha224 = 2,
    Sha256 = 3,
    Sha384 = 4,
    Sha512 = 5,

}
```

