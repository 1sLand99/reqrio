# reqrio-v0.3.0

`v0.3.0`是一次重要的架构升级，标志着 reqrio 从基础 HTTP 客户端，演进为具备 TLS / 流式处理能力的可控网络栈。

## ✨ 新特性

### 🔧 全新 HTTP API

* 重构请求接口，提升可读性与扩展性
* 为复杂请求场景与后续功能扩展打下基础

### 🌐 内置 ECH 查询支持

* 支持查询域名的 ECH（Encrypted ClientHello）配置
* 可基于查询结果构建 ECH 数据
* 为 TLS 指纹模拟与隐私增强连接提供基础能力

### 🌊 流式响应解析（Reader）

* 提供轻量级二进制解析工具（Reader）
* 支持类型：
    * u8 / u16 / u24 / u32
    * &[u8] / str
* 适用于 TLS / DNS / HTTP 等协议解析场景

## 🎯 指纹级网络行为控制（Fingerprint）

在 v0.3.0 中，Fingerprint 体系进行了重构，支持对 TLS 与 HTTP/2 行为的精细控制。

### 🔐 自定义 TLS 指纹

支持自定义：

* Cipher Suites
* Supported Groups
* Signature Algorithms
* TLS Versions
* Extensions 
* ...

```text
let tls = TlsFinger::Custom {
    suites: vec![CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.into(), ],
    groups: vec![NamedCurve::X25519.into()],
    algorithms: vec![SignatureAlgorithm::RSA_PSS_RSAE_SHA256.into()],
    versions: vec![Version::TLS_1_3, Version::TLS_1_2],
    ec_formats: vec![EcPointFormat::UNCOMPRESSED],
    compress_methods: vec![],
    extensions: vec![ExtensionType::StatusRequest],
};
```

👉 可用于：

* TLS 指纹模拟（如 JA3/JA4）
* 反爬对抗
* 协议研究

### ⚡ 自定义 HTTP/2 指纹

支持自定义 HTTP/2 设置帧与优先级参数：

```text
let h2 = H2Finger {
    setting: vec![
        H2Setting::EnablePush(0),
        H2Setting::HeaderTableSize(4096),
        H2Setting::InitialWindowSize(8192),
        H2Setting::MaxHeaderListSize(242144)
    ],
    window_size: 2147418112,
    weight: 234, //优先权重
    priority: true, //优先级
};
```

👉 可用于：

* 构造 HTTP/2 指纹（Settings / Window / Priority）
* 模拟浏览器网络行为
* 精细控制连接调度策略

## 🔐 支持 TLS 1.3

* 完整支持 TLS 1.3 握手流程
* 支持与自定义 TLS 指纹联动
* 为浏览器级 TLS 行为模拟提供基础

## Contact

* Tg: https://t.me/+VVfbAeug-ohhZjU1
* QQ: 1083315546


# reqrio-v0.2.0

`v0.2.0` focuses on improving the high-performance request streaming architecture and expanding the TLS capabilities of
reqtls.Several improvements were also added, including proxy authentication support, enhanced TLS algorithms, DNS
caching

## High speed low copy request stream

Starting from `v0.1.0`, reqrio introduces a high-speed request streaming architecture that minimizes memory allocations
and unnecessary data copies.

The new design removes most intermediate `String` and `Vec<u8>` allocations when building requests, significantly
improving
throughput and reducing memory pressure in high-concurrency scenarios.

* Data Flow

```text

        Data  ┌────────┐encode->bytes ┌──────────┐             ┌──────────┐
 User ───────►│        │─────────────►│          │             │          │
              │ ScReq  │              │  Request │ copy slice  │ fragment │ write ┌───────┐
              │ AcReq  │              │  borrow  │────────────►│  TLS     │──────►│  TCP  │
       Files  │(Engine)│ into_reader  │  buffer  │             │ Encrypt  │       └───────┘
 User ───────►│        │─────────────►│          │             │          │
              └────────┘              └──────────┘             └──────────┘
```

## `ReadExt` and `WriteExt`

Starting from `v0.2.0`, reqrio introduces two core I/O helpers: ReadExt and WriteExt. They are the foundation of the
high-speed request stream pipeline, enabling efficient construction of both HTTP request streams and TLS record streams
with minimal overhead.

```text
           Write                Read            
       Request Source         Tcp Socket     
             │                    │ Buffer           
             ▼                    ▼            
       RequestBuffer          TLS Record         
         (ReadExt)            (decrypt)
      Buffer │ copy          copy │ Buffer       
             ▼                    ▼            
         TLS Record             Buffer        
          (encrypt)           (H2Frame)      
             │                    │            
             ▼                    ▼            
          TCP Socket           Response      
```

## Certificate Issuer

Starting from `v0.2.0`, `reqtls` introduces a built-in certificate issuer, enabling the generation and signing of tls
certificates directly within the library.

This feature allows `reqtls` to act as a lightweight certificate authority (CA) capable of issuing:

* Root certificates

* Server certificates

* Client certificates

## mTLS Client

Starting from v0.2.0, `reqtls` adds support for mutual TLS (mTLS) on the client side.

With mTLS enabled, the client not only verifies the server certificate, but also presents its own certificate and
private key during the TLS handshake. This allows servers to authenticate the client identity, providing stronger
security than standard TLS.

Client mTLS can be enabled by configuring a client certificate and private key through `ClientConfig`.

* Example

```
 use reqrio::*;
 
 let mut req=ScReq::new();
 let certs=Certificate::from_pem_file("path/to/cert").unwrap();
 let key=RsaKey::from_pri_pem_file("path/to/cert/key").unwrap();
 req.set_mtls(certs,key);
```

## New Export

| No. | Function              | Params                                                   | Res    | Note                     |
|:---:|:----------------------|:---------------------------------------------------------|:-------|:-------------------------|
|  1  | Cipher_new            | CipherType                                               | void * |
|  2  | Cipher_set_secret_key | void *, const uint8_t *, size_t, const uint8_t *, size_t | int    |
|  3  | Cipher_encrypt        | void *, const uint8_t *, size_t, uint8_t **, size_t      | int    |
|  4  | Cipher_decrypt        | void *, const uint8_t *, size_t, uint8_t **, size_t      | int    |
|  5  | Cipher_free           | void *                                                   | -      | Destroy Cipher * pointer |
|  6  | Hasher_new            | HashType                                                 | void * |
|  7  | Hasher_update         | void *, const uint8_t *, size_t                          | int    |
|  8  | Hasher_finalize       | void *, uint8_t **, size_t                               | int    |
|  9  | Hasher_free           | void *                                                   | -      |
| 10  | Hmac_new              | uint8_t **, size_t, HashType                             | void * |
| 11  | Hmac_update           | void *, const uint8_t *, size_t                          | int    |
| 12  | Hmac_finalize         | void *, uint8_t **, size_t                               | int    |
| 13  | Hmac_free             | void *                                                   | -      |
| 14  | Base64_new            | -                                                        | void * |
| 15  | Base64_encode         | void *, const uint8_t *, size_t                          | char * |
| 16  | Base64_decode         | void *, const uint8_t *, size_t, uint8_t **, size_t      | int    |
| 17  | Base64_free           | void *                                                   | -      |
| 18  | url_encode            | const char *                                             | char * |
| 19  | url_decode            | const char *                                             | char * |
| 20  | hex_encode            | const unt8_t, size_t                                     | char * |
| 21  | hex_decode            | const char *, uint8_t **, size_t                         | int    |

## Other Update

### reqrio

- set_verify - verify server certificate information
- Add ` patch ` method
- set_auto_direct - does it automatically jump to 3xx state
- proxy: `socks5` and `http_plain` support username and password verification
- hpack—coding：Supports streaming hpack encoding and decoding

### reqtls

- Export `Cipher`, `Hmac`, `Base64`, `Hasher`, url_en(de)code, hex_en(de)code, and other C-ABI formats.

- Support `TLS_AES_CBC/128/256/SHA/SHA256/SHA384 algorithms`.

- Add `RecordEncodeBuffer` and `RecordDecodeBuffer`.

- Add DNS caching with a 30-minute cache time.

## Contact

* Tg: https://t.me/+VVfbAeug-ohhZjU1
* QQ: 1083315546

# reqrio-v0.1.0

### reqrio is an HTTP request library designed for fast, simple, and convenient HTTP request usage.

* Features: Low copy, high concurrency, low overhead

* Supports TLS fingerprinting, which can be configured via hexadecimal, Ja3, or Ja4 TLS handshake settings (*
  *subscription only**).

* Ensures **request header order** (see [Request Header Order Table](#request-header-order-table)), consistent with
  browsers.

* Uses **BoringSSL** to implement TLS, consistent with browsers like Chrome and Edge.

**Note:** std and cls cannot exist simultaneously, while sync and async can exist simultaneously.

### Request Header Order Table

| No. | HTTP/2.0                    | HTTP/1.1                  |
|:----|:----------------------------|:--------------------------|
| 1   | cache-control               | Host                      |
| 2   | sec-ch-ua                   | Connection                |
| 3   | sec-ch-ua-mobile            | Content-Length            |
| 4   | sec-ch-ua-full-version      | Authorization             |
| 5   | sec-ch-ua-arch              | Content-Type              |
| 6   | sec-ch-ua-platform          | Cache-Control             |
| 7   | sec-ch-ua-platform-version  | sec-ch-ua                 |
| 8   | sec-ch-ua-model             | sec-ch-ua-mobile          |
| 9   | sec-ch-ua-bitness           | sec-ch-ua-platform        |
| 10  | sec-ch-ua-full-version-list | Upgrade-Insecure-Requests |
| 11  | upgrade-insecure-requests   | User-Agent                |
| 12  | user-agent                  | Accept                    |
| 13  | accept                      | Sec-Fetch-Site            |
| 14  | origin                      | Sec-Fetch-Mode            |
| 15  | sec-fetch-site              | Sec-Fetch-User            |
| 16  | sec-fetch-mode              | Sec-Fetch-Dest            |
| 17  | sec-fetch-user              | Sec-Fetch-Storage-Access  |
| 18  | sec-fetch-dest              | Referer                   |
| 19  | sec-fetch-storage-access    | Accept-Encoding           |
| 20  | referer                     | Accept-Language           |
| 21  | accept-encoding             | Cookie                    |
| 22  | accept-language             | Origin                    |
| 23  | cookie                      |                           |
| 24  | priority                    |                           |
|     | //unknown                   |                           |
| 25  | content-encoding            |                           |
| 26  | content-type                |                           |
| 27  | authorization               |                           |
| 28  | content-type                |                           |

### reqrio export function

Reqrio has C export functions that can be called in different languages

| No. | Function                     | Params                                        | Res    |               Note                |
|:---:|:-----------------------------|:----------------------------------------------|:-------|:---------------------------------:|
|  1  | ScReq_new                    | -                                             | void * |
|  2  | ScReq_set_header_json        | void *, const char *                          | int    |
|  3  | ScReq_add_header             | void *, const char *, const char *            | int    |
|  4  | ScReq_set_alpn               | void *, const char *                          | int    |
|  5  | ScReq_set_random_fingerprint | void *                                        | int    |                                   |
|  6  | ScReq_set_fingerprint        | void *, const char *                          | int    |                                   |
|  7  | ScReq_set_ja3                | void *, const char *                          | int    |                                   |
|  8  | ScReq_set_ja4                | void *, const char *                          | int    |                                   |
|  9  | ScReq_set_proxy              | void *, const char *                          | int    |       http:// or socks5://        |
| 10  | ScReq_set_url                | void *, const char *                          | int    |  Called before setting the body   |
| 11  | ScReq_add_param              | void *, const char *, const char *            | int    |
| 12  | ScReq_set_data               | void *, const char *                          | int    |
| 13  | ScReq_set_json               | void *, const char *                          | int    |
| 14  | ScReq_set_bytes              | void *, const char *, uint32_t                | int    |
| 15  | ScReq_set_text               | void *, const char *                          | int    |
| 16  | ScReq_set_timeout            | void *, const char *                          | int    |   Tiemout structure to JSON str   |
| 17  | ScReq_set_cookie             | void *, const char *                          | int    |
| 18  | ScReq_add_cookie             | void *, const char *, const char *            | int    |
| 19  | ScReq_set_callback           | void *, extern "C" fn(const char *, uint32_t) | int    |
| 20  | ScReq_reconnect              | void *                                        | int    |
| 21  | ScReq_stream_io              | void *, Method                                | char * |       Return to hexadecimal       |
| 22  | ScReq_drop                   | void *                                        | -      |   Destroy the new_tttp instance   |
| 23  | char_free                    | char *                                        | -      |      Destroy char * pointer       |
| 24  | ws_build                     | -                                             | void * |
| 25  | ws_add_header                | void *, const char *, const char *            | int    |
| 26  | ws_set_proxy                 | void *, const char *                          | int    | The value is http:// or socks5:// |
| 27  | ws_set_url                   | void *, const char *                          | int    |
| 28  | ws_set_uri                   | void *, const char *                          | int    |
| 29  | ws_open                      | void *                                        | void * |
| 30  | ws_open_raw                  | const char *, const char *                    | void * |
| 31  | ws_read                      | void *                                        | char * |          Return as JSON           |
| 32  | ws_write                     | void *, int, bool, const char *               | int    |          opcode,mask,msg          |
| 33  | ws_close                     | void *                                        | -      |        Destroy WS instance        |

* When the function returns -1, the function is unavailable
* The instance needs to be manually released, otherwise it may cause memory leakage

# reqtls-v0.1.0

### reqtls is a lightweight TLS library and encryption/decryption library.

&nbsp;&nbsp;&nbsp;&nbsp;reqtls is built on boringssl and maintains consistency with browser behavior.

### Encryption/decryption support：

* aes_ecb_128
* aes_ecb_192
* aes_ecb_256
* aes_cbc_128
* aes_cbc_192
* aes_cbc_256
* aes_crt_128
* aes_crt_192
* aes_crt_256
* aes_gcm_192
* aes_gcm_256
* aes_gcm_128
* aes_ofb_192
* aes_ofb_256
* aes_ofb_128
* des_ecb
* des_cbc
* rsa

### TLS supports TLS 1.2.

* aes-gcm-128
* aes-gcm-256
* chacha20_poly1305
* x25519
* secp256r1
* secp384r1
* secp521r1

### CipherSuite

* TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
* TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
*
* TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
* TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
* TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256

* TLS_RSA_WITH_AES_128_GCM_SHA256
* TLS_RSA_WITH_AES_256_GCM_SHA384

### AlgorithmSignature

* RSA_PSS_RSAE_SHA256
* RSA_PSS_RSAE_SHA384
* RSA_PSS_RSAE_SHA512
* ECDSA_SECP256R1_SHA256
* ECDSA_SECP384R1_SHA384
* ECDSA_SECP521R1_SHA512
* RSA_PKCS1_SHA1
* RSA_PKCS1_SHA256
* RSA_PKCS1_SHA384
* RSA_PKCS1_SHA512

### Hash support

* sha1
* sha224
* sha256
* sha385
* sha512
* hmac

### Encoding support

* base64
* urlencoding
* hex

### Compression Support

* gzip
* deflate
* br
* zstd