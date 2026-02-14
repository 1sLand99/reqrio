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