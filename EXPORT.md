### reqrio export function

| No. | Function                     | Params                                                   | Res    |               Note                |
|:---:|:-----------------------------|:---------------------------------------------------------|:-------|:---------------------------------:|
|  1  | ScReq_new                    | -                                                        | void * |
|  2  | ScReq_set_header_json        | void *, const char *                                     | int    |
|  3  | ScReq_add_header             | void *, const char *, const char *                       | int    |
|  4  | ScReq_set_alpn               | void *, const char *                                     | int    |
|  5  | ScReq_set_verify             | void *, const char *                                     | -      |
|  6  | ScReq_set_random_fingerprint | void *, const char *                                     | int    |     Return -2 as unsubscribed     |
|  7  | ScReq_set_fingerprint        | void *, const char *, const char *                       | int    |     Return -2 as unsubscribed     |
|  8  | ScReq_set_ja3                | void *, const char *, const char *                       | int    |     Return -2 as unsubscribed     |
|  9  | ScReq_set_ja4                | void *, const char *, const char *                       | int    |     Return -2 as unsubscribed     |
| 10  | ScReq_set_proxy              | void *, const char *                                     | int    |       http:// or socks5://        |
| 11  | ScReq_set_url                | void *, const char *                                     | int    |  Called before setting the body   |
| 12  | ScReq_add_param              | void *, const char *, const char *                       | int    |
| 13  | ScReq_set_data               | void *, const char *                                     | int    |
| 14  | ScReq_set_json               | void *, const char *                                     | int    |
| 15  | ScReq_set_bytes              | void *, const char *, uint32_t                           | int    |
| 16  | ScReq_set_text               | void *, const char *                                     | int    |
| 17  | ScReq_set_timeout            | void *, const char *                                     | int    |   Tiemout structure to JSON str   |
| 18  | ScReq_set_cookie             | void *, const char *                                     | int    |
| 19  | ScReq_add_cookie             | void *, const char *, const char *                       | int    |
| 20  | ScReq_set_callback           | void *, extern "C" fn(const char *, uint32_t)            | int    |
| 21  | ScReq_reconnect              | void *                                                   | int    |
| 22  | ScReq_stream_io              | void *, Method                                           | char * |       Return to hexadecimal       |
| 23  | ScReq_drop                   | void *                                                   | -      |   Destroy the new_tttp instance   |
| 24  | ws_build                     | -                                                        | void * |
| 25  | ws_add_header                | void *, const char *, const char *                       | int    |
| 26  | ws_set_proxy                 | void *, const char *                                     | int    | The value is http:// or socks5:// |
| 27  | ws_set_url                   | void *, const char *                                     | int    |
| 28  | ws_set_uri                   | void *, const char *                                     | int    |
| 29  | ws_open                      | void *                                                   | void * |
| 30  | ws_open_raw                  | const char *, const char *                               | void * |
| 31  | ws_read                      | void *                                                   | char * |          Return as JSON           |
| 32  | ws_write                     | void *, int, bool, const char *                          | int    |          opcode,mask,msg          |
| 33  | ws_close                     | void *                                                   | -      |        Destroy WS instance        |
| 34  | Cipher_new                   | CipherType                                               | void * |
| 35  | Cipher_set_secret_key        | void *, const uint8_t *, size_t, const uint8_t *, size_t | int    |
| 36  | Cipher_encrypt               | void *, const uint8_t *, size_t, uint8_t **, size_t      | int    |
| 37  | Cipher_decrypt               | void *, const uint8_t *, size_t, uint8_t **, size_t      | int    |
| 38  | Cipher_free                  | void *                                                   | -      |     Destroy Cipher * pointer      |
| 39  | Hasher_new                   | HashType                                                 | void * |
| 40  | Hasher_update                | void *, const uint8_t *, size_t                          | int    |
| 41  | Hasher_finalize              | void *, uint8_t **, size_t                               | int    |
| 42  | Hasher_free                  | void *                                                   | -      |
| 43  | Hmac_new                     | uint8_t **, size_t, HashType                             | void * |
| 44  | Hmac_update                  | void *, const uint8_t *, size_t                          | int    |
| 45  | Hmac_finalize                | void *, uint8_t **, size_t                               | int    |
| 46  | Hmac_free                    | void *                                                   | -      |
| 47  | Base64_new                   | -                                                        | void * |
| 48  | Base64_encode                | void *, const uint8_t *, size_t                          | char * |
| 49  | Base64_decode                | void *, const uint8_t *, size_t, uint8_t **, size_t      | int    |
| 50  | Base64_free                  | void *                                                   | -      |
| 51  | url_encode                   | const char *                                             | char * |
| 52  | url_decode                   | const char *                                             | char * |
| 53  | hex_encode                   | const unt8_t, size_t                                     | char * |
| 54  | hex_decode                   | const char *, uint8_t **, size_t                         | int    |
| 55  | char_free                    | char *                                                   | -      |      Destroy char * pointer       |
| 56  | u8_free                      | uint8_t *, size_t                                        | -      |     Destroy uint8_t * pointer     |

* When the function returns -1, the execution fails; -2 is in non subscription status and the function is unavailable
* The instance needs to be manually released, otherwise it may cause memory leakage

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