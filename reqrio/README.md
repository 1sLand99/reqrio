#### `reqrio` is an HTTP request library designed to enable quick, simple, and convenient use of HTTP requests.

* reqrio features: low copying, high concurrency, low overhead
* Reqrio supports TLS fingerprinting, which can be set via hexadecimal or Ja3 data from the TLS handshake. Only cls_sync
  and cls_async are supported (**subscription only**).
* By default, reqrio will reorder the request headers in the same way as the browser (it will reorder the request
  headers).
* CLS mode uses BoringSSL, consistent with browsers such as Chrome and Edge.

#### By default, reqrio does not enable HTTP requests; it is only exported as an HTTP data stream parsing library. Requests require features to be enabled.

* `std_sync`: Standard TLS library ([rustls](https://github.com/rustls/rustls), synchronous requests)
* `std_async`: Standard TLS library ([tokio-rustls](https://github.com/rustls/tokio-rustls), asynchronous requests)
* `cls_sync`: Self-developed TLS library (**Algorithm is imperfect, does not verify server certificates, do not use in
  production mode**) [reqtls](https://github.com/xllgl2017/reqrio/tree/master/reqtls), synchronous requests
* `cls_async`: Self-developed TLS library (**Algorithm is imperfect, does not verify server certificates, do not use in
  production mode**) [reqtls](https://github.com/xllgl2017/reqrio/tree/master/reqtls), asynchronous requests

**Note:** std and cls cannot exist simultaneously, while sync and async can exist simultaneously.

### Usage examples (supports Rust, Python, Java and Node.js):

* Rust HTTP Example

```rust
use reqrio::{Fingerprint, ScReq, ALPN};

fn ff() {
    let fingerprint = Fingerprint::default().unwrap();
    fingerprint.set_ja3("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,13-11-65037-17613-45-18-16-5-43-10-0-27-23-35-51-65281,4588-29-23-24,0");
    let req = ScReq::new()
        //The default is to use http/1.1
        .with_alpn(ALPN::Http20)
        .with_fingerprint(fingerprint)
        .with_url("https://www.baidu.com").unwrap();
    let headers = json::object! {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "Cookie": "__guid=15015764.1071255116101212729.1764940193317.2156; env_webp=1; _S=pvc5q7leemba50e4kn4qis4b95; QiHooGUID=4C8051464B2D97668E3B21198B9CA207.1766289287750; count=1; so-like-red=2; webp=1; so_huid=114r0SZFiQcJKtA38GZgwZg%2Fdit1cjUGuRcsIL2jTn4%2FE%3D; __huid=114r0SZFiQcJKtA38GZgwZg%2Fdit1cjUGuRcsIL2jTn4%2FE%3D; gtHuid=1",
        "Host": "m.so.com",
        "Pragma": "no-cache",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": 1,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0",
        "sec-ch-ua": r#""Microsoft Edge";v="143", "Chromium";v="143", "Not A(Brand";v="24""#,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": r#""Windows""#
    };
    //By default, there are no request headers; you need to configure them yourself.
    req.set_headers_json(header);
    let res = req.get().unwrap();
    //Get response headers
    let header = res.header();
    //Get the response body; the body here has already been decoded.
    let body = res.decode_body().unwrap();
    //Try decoding to JSON
    let json = res.to_json().unwrap();
}
```

* Rust WebSocket Example

```rust
use reqrio::*;

fn ff() {
    let mut ws = WebSocket::sync_build()
        .with_url("wss://poe.game.qq.com/").unwrap()
        .with_uri("wss://poe.game.qq.com/api/trade2/live/poe2/%E7%93%A6%E5%B0%94%E7%9A%84%E5%AE%BF%E5%91%BD/32Y6Wjkc5").unwrap()
        .with_origin("https://poe.game.qq.com").unwrap()
        .with_cookie("pac_uid=0_NattYaCs7NNmH; omgid=0_NattYaCs7NNmH; _qimei_uuid42=19c1f11150d1000f92fe16d850a9c40cf94ef1d39f; _qimei_fingerprint=f3dc39297e432b1f08da57e9904a8f52; _qimei_q36=; _qimei_h38=a549811f92fe16d850a9c40c02000006b19c1f; _qpsvr_localtk=0.2296543129537577; RK=WPZCq/wl3I; ptcz=c338dead622f05f0d8467ac10589e7e45326b81d67ff476b9643f933cfdc644a; eas_sid=M1b7q677w9D5R5P2L8x5g4p313; eas_entry=https%3A%2F%2Fgraph.qq.com%2F; POESESSID=939e23af876572a0b2852b2e183e20cc").unwrap()
        .with_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0").unwrap()
        .build().unwrap();
    loop {
        let res = ws.read_frame().unwrap();
        match res.frame_type().op_code() {
            WsOpcode::CONTINUATION => {}
            WsOpcode::TEXT => println!("{}", res.payload().as_bytes().len()),
            WsOpcode::BINARY => {}
            WsOpcode::CLOSE => {}
            WsOpcode::PING => {
                println!("PING");
                let pong = WsFrame::new_pong(true, res.payload().as_bytes());
                ws.write_frame(pong).unwrap();
            }
            WsOpcode::PONG => {}
        }
    }
}
```

* Python examples

```python
import reqrio

# The default is to use http/1.1
# * If the same session uses the same TCP connection, it will automatically reconnect upon disconnection.
session = reqrio.Session(alpn=reqrio.ALPN.HTTP20)
tls_fingerprint = "16030106b2010006ae0303f0aed3d4d9fac0e8d4ff98981a90257765d203b4ce089c591e86d8e7ec8ab90a204803c2150a14429bfe6536328fe11cfd4034264fa2a3a443c5972eeeb93d427100206a6a130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035010006453a3a000000230000001b0003020002ff010001000000000e000c0000093338686d7a672e636e0005000501000000000017000044cd00050003026832fe0d00ba00000100010900208e3fc249e1ce71ff4aefb0970b38167b6b7de98537b874130ba4e284e15f1c4f00909540fc3a77fcc8f96d51ff9144785ccf114d3618d9a77b0e88f54d4dd1279083483e0ad83a4f25e55951194048709bf0842651d940c291569b9cfe1323d6fc2d31348ccaaa7b79271fc41af0975d94f7a826819154e05f6f90bdaa4e2b215894ccd36f748ded2bcae0a61aa101a7187588c2b45b51d076356d0e47728974d6d1cdd2b3ce4a8e5e8f70a79fb8f288c868000b00020100002d00020101000a000c000a3a3a11ec001d00170018001200000010000e000c02683208687474702f312e31003304ef04ed3a3a00010011ec04c05b20439ba8b50e3a5800981889512ab253cd2f1ba1488613fbd79f43813c08e34ed45330a62991a6b37890d54d2d0c089251b146acace84512c031c74ac6a2ac6345b6668629aa143357b45921916de02ac5cc8d57e1ca9882ccad900640a1b51c587de3291a2f15ad67e180b79b442fe4606de978f7a27591a41ffcd91116c50703c45531999c9d377a173c249ef747a60a81158c0d3ef709b9b5a38af61b6b5c9740c343f7322b6510a60797cb39148ba310413b688354bb0b2e395dbf3935fd0a797d7b5e94acab23a95c163238dd1bc9b8b420599a0efd4726e85a0783fc8506436c3eb89ee96008b0c9c5a2047a2415bbb5a2768d7c8d58384644d5473de96721b24a3fc82ee68cc0a3a43cc73467ec515a3ac1a79b9070f4e4aad61ac50c7b4e9b125f66cba026807cdad5a43e4a5cfa2ac521801616bb58ea068689c15afd4592b26545c3a8c638800a3429c32237a902f1a605458935391c4d352a211cb2122203f9ea38e3d44b29741502bb57c7850ffaf36ab0db72ac9c0fc0ba309661096bc550d86b442beca080c0602e02a54ed2171e58b0b82582c568a5b1407d8d35448cf907a43575aed4c5371595d1456f29778c892325d4d785a3a384a30b838e6b0d59990ca54ba52369c4faf835a2f50cbd504f7d38cdc4047bf7acae92090cf121180096a513dc4cadf290641ab6e4375aa477395b8902b74c39e62b945a09438d83b1d41ac2f204c4614425bed86e221c60c8520e1c3233e5ccb53c228c0d525fb7823d9d9c4337e36785eb61590794f9565b3dd2722a2834b536be157a307d928d7f910167a314b8705bdddc1b4c9c139a5320380910b1263b40a6c6065c84266a2c036a19d3a51f5edbb8eaf3cb1e8295ef1ab978f5306da9b11a5a3df473bbd2acca084a4c4bba0bc478630283b0e6910bde3052c6f58300703a6e9524381b4cc1b247236acc1c0bae6cb69c463c29811b04d93a589ba36d30c9b4d1fb234368a9b3e94abaf419a220af730917488bc9be585f7111c9a13a8544969bf3e397b1f2ceba0ca7f21785531a3f7856248f54a5bd854124b21e1e75c366e8b5293130bdb902db0a05e9803c3d7827d5cc26046815102c3713b4a14ef63aed3163319244995a6524dbabfaf93ed8a95e08641377683dd6b3b05084bf48f77d47904d09656d4a19b457d84bcfd77a4c433393bbb43f09931cf4896cf891990c9363202467b6193ea6b8bd493733235c93c118feb808b1d9b38cc7862c744342e2baeeec6299d0a21898aa9576ae61b2703a5b072521166f6693aa4b5e6148ad4e7c21a21a7972a0c8c3f986e95392ed2b15e51a5f2e5b90e4766320513e3bfa4d67688fb6c547147c47aa71c04095336b11b32b52a6c9d047a1357eece2688efb2045184653a480ef15a3fb8c4851d8c0407b24a87b55fd36af59b18fff38b183b6256e15c161395a46f62ce1b0af240319dec84d3aa04e2773ac289b393160683e901b2b622d615b2719b06cc12bae79fca101e737a91434c8e0828cc6a71b740216964a06a9952d9c54f24743b1b9c4fc9475554aa8a87719ccd7ae40374c87d8018937c7b6007e028b348e884d201087416396ec3237b61319e0f40e436a6a1dc75f2486a68c60c27f719d251a9d73b3de3bd91858d3f3d4043384f7ad42422b47b96bdd03b5556f8107232953dad801970157aa95971638e2908d55001d0020552cb65392fdab1ff61dd3b43c895fdf782c61bb6f05519f2b7d9e28facfd25e000d0012001004030804040105030805050108060601002b000706dada030403031a1a0001001603030046100000424104ff635373fbbfbc37444a2026372f57fd06c5205bacfe32b61261a9d29bf1fca57f91ef22cb2ba46af8cf9ae7c3123f56634099af297dcd30835cd81664005fb9140303000101"
session.set_fingerprint(tls_fingerprint)
# session.set_ja3("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,45-11-5-51-0-43-10-35-27-17513-23-65037-16-18-13-65281,4588-29-23-24,0")
headers = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    # "Cookie": "__guid=15015764.1071255116101212729.1764940193317.2156; env_webp=1; _S=pvc5q7leemba50e4kn4qis4b95; QiHooGUID=4C8051464B2D97668E3B21198B9CA207.1766289287750; count=1; so-like-red=2; webp=1; so_huid=114r0SZFiQcJKtA38GZgwZg%2Fdit1cjUGuRcsIL2jTn4%2FE%3D; __huid=114r0SZFiQcJKtA38GZgwZg%2Fdit1cjUGuRcsIL2jTn4%2FE%3D; gtHuid=1",
    # "Host": "m.so.com",It's best not to manually set the host value; let the underlying system automatically add it to avoid host conflicts when using different connections within the same session.
    "Pragma": "no-cache",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": 1,
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0",
    "sec-ch-ua": '"Microsoft Edge";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"'
}
# By default, there are no request headers; you need to configure them yourself.
session.set_header_json(headers)
# Set timeout
session.set_timeout(3, 3, 3, 3)
resp = session.get('https://m.so.com')
# Get response headers
print(resp.header.__dict__)
# Get the response body
print(resp.text())
# Try decoding to JSON
print(resp.json())

# Here, instead of establishing a new connection, the previous TCP connection is reused.
stream = session.open_stream('https://m.so.com/', reqrio.Method.GET)
for bs in stream:
    # Processing data streams
    print(len(bs))
# Get the returned response headers
print(stream.response.header.__dict__)

# Close the connection resource, remember to call...
session.close()
```

* Java example

```java
import com.google.gson.Gson;
import org.xllgl2017.*;

void main() throws Exception {
    //Initialization allows you to set the version.
    Reqrio reqrio = new Reqrio(ALPN.HTTP11);
    //Initialize header
    Headers headers = new Headers();
    headers.addHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7");
    headers.addHeader("Accept-Encoding", "gzip, deflate, br, zstd");
    headers.addHeader("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6");
    headers.addHeader("Cache-Control", "no-cache");
    headers.addHeader("Connection", "keep-alive");
    headers.addHeader("Host", "m.so.com");
    headers.addHeader("Pragma", "no-cache");
    headers.addHeader("Sec-Fetch-Dest", "document");
    headers.addHeader("Sec-Fetch-Mode", "navigate");
    headers.addHeader("Sec-Fetch-Site", "none");
    headers.addHeader("Sec-Fetch-User", "?1");
    headers.addHeader("Upgrade-Insecure-Requests", "1");
    headers.addHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0");
    headers.addHeader("sec-ch-ua", "\"Microsoft Edge\";v=\"143\", \"Chromium\";v=\"143\", \"Not A(Brand\";v=\"24\"");
    headers.addHeader("sec-ch-ua-mobile", "?0");
    headers.addHeader("sec-ch-ua-platform", "\"Windows\"");
    //You can also add cookies using reqrio.setCookie.
    headers.setCookies("__guid=15015764.1071255116101212729.1764940193317.2156; env_webp=1; _S=pvc5q7leemba50e4kn4qis4b95; QiHooGUID=4C8051464B2D97668E3B21198B9CA207.1766289287750; count=1; so-like-red=2; webp=1; so_huid=114r0SZFiQcJKtA38GZgwZg%2Fdit1cjUGuRcsIL2jTn4%2FE%3D; __huid=114r0SZFiQcJKtA38GZgwZg%2Fdit1cjUGuRcsIL2jTn4%2FE%3D; gtHuid=1");
    //Set header
    reqrio.setHeaders(headers);
    //Set timeout
    Timeout timeout = new Timeout();
    reqrio.setTimeout(timeout);
    //ask
    Response response = reqrio.get("https://m.so.com");
    IO.println(response.length());
    Headers resp_hdr = response.getHeader();
    Gson gson = new Gson();
    IO.println(gson.toJson(resp_hdr));
}
```

* Qt Example

```c++
#include "Session.h"

int main(int argc, char *argv[]) {
    Session session(HTTP11);
    session.add_header("User-Agent",
                       "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.6894.1545 Safari/537.36");
    session.add_header("Accept", "*/*");
    session.add_header("Accept-Encoding", "gzip");
    session.add_header("Accept-Language", "zh-CN,zh;q=0.9");
    session.add_header("Sec-Fetch-Site", "same-origin");
    session.add_header("Sec-Fetch-Mode", "cors");
    session.add_header("Sec-Fetch-Dest", "empty");
    session.add_header("sec-ch-ua", "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"42\", \"Microsoft Edge\";v=\"42\"");
    session.add_header("sec-ch-ua-mobile", "?0");
    session.add_header("sec-ch-ua-platform", "\"Windows\"");
    auto timeout = Timeout(2000, 1000, 1000, 2000, 1, 1);
    session.set_timeout(timeout);
    session.setUrl("https://www.baidu.com");
    Response resp = session.get();
    qDebug()<<resp.toString();
}

```

* Node.js Example

```js
const {Session, ALPN} = require("./session")

let session = new Session(ALPN.HTTP11)
session.set_header_json({
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    "Cookie": "__guid=15015764.1071255116101212729.1764940193317.2156; env_webp=1; _S=pvc5q7leemba50e4kn4qis4b95; QiHooGUID=4C8051464B2D97668E3B21198B9CA207.1766289287750; count=1; so-like-red=2; webp=1; so_huid=114r0SZFiQcJKtA38GZgwZg%2Fdit1cjUGuRcsIL2jTn4%2FE%3D; __huid=114r0SZFiQcJKtA38GZgwZg%2Fdit1cjUGuRcsIL2jTn4%2FE%3D; gtHuid=1",
    "Host": "m.so.com",
    "Pragma": "no-cache",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": 1,
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0",
    "sec-ch-ua": '"Microsoft Edge";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"'
})
session.set_url('https://m.so.com')
let resp = session.get()
console.log(resp.status_code())
session.close()

```

### reqrio export function

| No. |                        | Function                                      | Params |                Res                | Note |
|:---:|------------------------|:----------------------------------------------|:-------|:---------------------------------:|:----:|
|  1  | new_http               | -                                             | void * |
|  2  | set_header_json        | void *, const char *                          | int    |
|  3  | add_header             | void *, const char *, const char *            | int    |
|  4  | set_alpn               | void *, const char *                          | int    |
|  5  | set_random_fingerprint | void *                                        | int    |     Return -2 as unsubscribed     |
|  6  | set_fingerprint        | void *, const char *                          | int    |     Return -2 as unsubscribed     |
|  7  | set_ja3                | void *, const char *                          | int    |     Return -2 as unsubscribed     |
|  8  | set_ja4                | void *, const char *                          | int    |     Return -2 as unsubscribed     |
|  9  | set_proxy              | void *, const char *                          | int    |       http:// or socks5://        |
| 10  | set_url                | void *, const char *                          | int    |  Called before setting the body   |
| 11  | add_param              | void *, const char *, const char *            | int    |
| 12  | set_data               | void *, const char *                          | int    |
| 13  | set_json               | void *, const char *                          | int    |
| 14  | set_bytes              | void *, const char *, uint32_t                | int    |
| 15  | set_text               | void *, const char *                          | int    |
| 16  | set_timeout            | void *, const char *                          | int    |   Tiemout structure to JSON str   |
| 17  | set_cookie             | void *, const char *                          | int    |
| 18  | add_cookie             | void *, const char *, const char *            | int    |
| 19  | reconnect              | void *                                        | int    |
| 20  | get                    | void *                                        | char * |
| 21  | post                   | void *                                        | char * |
| 22  | options                | void *                                        | char * |
| 23  | put                    | void *                                        | char * |
| 24  | delete                 | void *                                        | char * |
| 25  | trach                  | void *                                        | char * |
| 26  | destroy                | void *                                        | -      |   Destroy the new_tttp instance   |
| 27  | free_pointer           | char *                                        | -      |      Destroy char * pointer       |
| 28  | register               | void *, extern "C" fn(const char *, uint32_t) | int    |
| 29  | build_ws               | -                                             | void * |
| 30  | ws_add_header          | void *, const char *, const char *            | int    |
| 31  | ws_set_proxy           | void *, const char *                          | int    | The value is http:// or socks5:// |
| 32  | ws_set_url             | void *, const char *                          | int    |
| 33  | ws_set_uri             | void *, const char *                          | int    |
| 34  | open_ws                | void *                                        | void * |
| 35  | open_ws_raw            | void *, const char *                          | void * |
| 36  | ws_read                | void *                                        | char * |          Return as JSON           |
| 37  | ws_write               | void *, int, bool, const char *               | int    |          opcode,mask,msg          |
| 38  | ws_close               | void *                                        | -      |        Destroy WS instance        |

* When the function returns -1, the execution fails; -2 is in non subscription status and the function is unavailable
* The instance needs to be manually released, otherwise it may cause memory leakage