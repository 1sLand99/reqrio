### reqrio is an HTTP request library designed for fast, simple, and convenient HTTP request usage.

* Features: Low copy, high concurrency, low overhead

* Supports TLS fingerprinting, which can be configured via hexadecimal, Ja3, or Ja4 TLS handshake settings (*
  *subscription only**).

* Ensures **request header order** (see [Request Header Order Table](#request-header-order-table)), consistent with
  browsers.

* Uses **BoringSSL** to implement TLS, consistent with browsers like Chrome and Edge.

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

### Usage examples (supports Rust, Python, Java and Node.js):

* Rust HTTP Example

```rust
use reqrio::{Fingerprint, ScReq, ALPN};

fn ff() {
    let req = ScReq::new()
        //The default is to use http/1.1
        .with_alpn(ALPN::Http20)
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
session.set_timeout(3000, 3000, 3000, 3000)
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
session.set_headers({
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

* go Example

```go
package main

import (
	"fmt"
	"reqrio-go/reqrio"
)

func main() {
	session := reqrio.NewSession()
	e1 := session.SetAlpn(reqrio.HTTP20)
	if e1 != nil {
		println(e1.Error())
	}
	headers := `{
	"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
	"Accept": "*/*",
	"Sec-Fetch-Site": "none",
	"Sec-Fetch-Mode": "navigate",
	"Sec-Fetch-Dest": "document",
	"sec-fetch-user": "?1",
	"upgrade-insecure-requests": "1",
	"sec-ch-ua": "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Microsoft Edge\";v=\"120\"",
	"sec-ch-ua-mobile": "?0",
	"sec-ch-ua-platform": "\"Windows\"",
	"Accept-Language": "zh-CN,zh;q=0.9",
	"Accept-Encoding": "gzip,deflate,br,zstd",
	"Cache-Control": "no-cache",
	"Connection": "keep-alive"
}`
	err1 := session.SetHeaderJson(headers)
	if err1 != nil {
		println(err1.Error())
	}
	err := session.SetUrl("https://m.so.com")
	if err != nil {
		println(err.Error())
		return
	}
	resp, err := session.Get()
	if err != nil {
		println(err.Error())
		return
	}
	//println(resp.Text())
	fmt.Printf("%#v\n", resp.Header())
	session.Close()
}

```

### reqrio export function

| No. | Function                     | Params                                        | Res    |               Note                |
|:---:|:-----------------------------|:----------------------------------------------|:-------|:---------------------------------:|
|  1  | ScReq_new                    | -                                             | void * |
|  2  | ScReq_set_header_json        | void *, const char *                          | int    |
|  3  | ScReq_add_header             | void *, const char *, const char *            | int    |
|  4  | ScReq_set_alpn               | void *, const char *                          | int    |
|  5  | ScReq_set_verify             | void *, const char *                          | -      |
|  6  | ScReq_set_random_fingerprint | void *, const char *                          | int    |     Return -2 as unsubscribed     |
|  7  | ScReq_set_fingerprint        | void *, const char *, const char *            | int    |     Return -2 as unsubscribed     |
|  8  | ScReq_set_ja3                | void *, const char *, const char *            | int    |     Return -2 as unsubscribed     |
|  9  | ScReq_set_ja4                | void *, const char *, const char *            | int    |     Return -2 as unsubscribed     |
| 10  | ScReq_set_proxy              | void *, const char *                          | int    |       http:// or socks5://        |
| 11  | ScReq_set_url                | void *, const char *                          | int    |  Called before setting the body   |
| 12  | ScReq_add_param              | void *, const char *, const char *            | int    |
| 13  | ScReq_set_data               | void *, const char *                          | int    |
| 14  | ScReq_set_json               | void *, const char *                          | int    |
| 15  | ScReq_set_bytes              | void *, const char *, uint32_t                | int    |
| 16  | ScReq_set_text               | void *, const char *                          | int    |
| 17  | ScReq_set_timeout            | void *, const char *                          | int    |   Tiemout structure to JSON str   |
| 18  | ScReq_set_cookie             | void *, const char *                          | int    |
| 19  | ScReq_add_cookie             | void *, const char *, const char *            | int    |
| 20  | ScReq_set_callback           | void *, extern "C" fn(const char *, uint32_t) | int    |
| 21  | ScReq_reconnect              | void *                                        | int    |
| 22  | ScReq_stream_io              | void *, Method                                | char * |       Return to hexadecimal       |
| 23  | ScReq_drop                   | void *                                        | -      |   Destroy the new_tttp instance   |
| 24  | char_free                    | char *                                        | -      |      Destroy char * pointer       |
| 25  | ws_build                     | -                                             | void * |
| 26  | ws_add_header                | void *, const char *, const char *            | int    |
| 27  | ws_set_proxy                 | void *, const char *                          | int    | The value is http:// or socks5:// |
| 28  | ws_set_url                   | void *, const char *                          | int    |
| 29  | ws_set_uri                   | void *, const char *                          | int    |
| 30  | ws_open                      | void *                                        | void * |
| 31  | ws_open_raw                  | const char *, const char *                    | void * |
| 32  | ws_read                      | void *                                        | char * |          Return as JSON           |
| 33  | ws_write                     | void *, int, bool, const char *               | int    |          opcode,mask,msg          |
| 34  | ws_close                     | void *                                        | -      |        Destroy WS instance        |

* When the function returns -1, the execution fails; -2 is in non subscription status and the function is unavailable
* The instance needs to be manually released, otherwise it may cause memory leakage