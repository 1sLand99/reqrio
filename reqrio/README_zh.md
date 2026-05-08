# 📦 reqrio - 一个轻量、高性能、指纹级的HTTP 请求库

## ✨ 特性
* 高并发与低内存开销
* 流式数据处理
* 为协议研究 / 反爬 / 指纹控制提供基础能力
* 支持tls指纹，可以通过tls握手的十六进制、ja3、ja4设置(**仅订阅**),
* 对**请求头进行排序**(查看[请求头顺序表](#请求头顺序表))，和浏览器一致
* 使用**BoringSSL**实现Tls，和浏览器chrome、edge等一致。
* 支持大文件流式发送

### 🌊 流式请求和解析

`reqrio` 是一个 低拷贝（low-copy）请求发送引擎，用于高效地将 用户数据或文件数据 通过 TLS 加密后发送到 TCP。`reqrio`
针对用户传入form-data、json、bytes、text等数据进行转bytes储存，然后仅在进入 TLS 加密阶段时发生一次 copy， 其余阶段仅对数据进行
borrow（借用）。对文件上传则通过into_reader进行读取，减小内存开销

```text

        Form  ┌────────┐encode->bytes ┌──────────┐             ┌──────────┐
 User ───────►│        │─────────────►│          │             │          │
        Json  │ ScReq  │  into_bytes  │  Request │ copy slice  │ fragment │ write ┌───────┐
              │ AcReq  │              │  borrow  │────────────►│  TLS     │──────►│  TCP  │
       Files  │(Engine)│ into_reader  │  reader  │             │ Encrypt  │       └───────┘
 User ───────►│        │─────────────►│          │             │          │
              └────────┘              └──────────┘             └──────────┘
```

### 请求头顺序表

| 编号 | HTTP/2.0                    | HTTP/1.1                  |
|:---|:----------------------------|:--------------------------|
| 1  | cache-control               | Host                      |
| 2  | sec-ch-ua                   | Connection                |
| 3  | sec-ch-ua-mobile            | Content-Length            |
| 4  | sec-ch-ua-full-version      | Authorization             |
| 5  | sec-ch-ua-arch              | Content-Type              |
| 6  | sec-ch-ua-platform          | Cache-Control             |
| 7  | sec-ch-ua-platform-version  | sec-ch-ua                 |
| 8  | sec-ch-ua-model             | sec-ch-ua-mobile          |
| 9  | sec-ch-ua-bitness           | sec-ch-ua-platform        |
| 10 | sec-ch-ua-full-version-list | Upgrade-Insecure-Requests |
| 11 | upgrade-insecure-requests   | User-Agent                |
| 12 | user-agent                  | Accept                    |
| 13 | accept                      | Sec-Fetch-Site            |
| 14 | origin                      | Sec-Fetch-Mode            |
| 15 | sec-fetch-site              | Sec-Fetch-User            |
| 16 | sec-fetch-mode              | Sec-Fetch-Dest            |
| 17 | sec-fetch-user              | Sec-Fetch-Storage-Access  |
| 18 | sec-fetch-dest              | Referer                   |
| 19 | sec-fetch-storage-access    | Accept-Encoding           |
| 20 | referer                     | Accept-Language           |
| 21 | accept-encoding             | Cookie                    |
| 22 | accept-language             | Origin                    |
| 23 | cookie                      |                           |
| 24 | priority                    |                           |
|    | //unknown                   |                           |
| 25 | content-encoding            |                           |
| 26 | content-type                |                           |
| 27 | authorization               |                           |
| 28 | content-type                |                           |

## 🚀 快速开始

* 初始化Session
```rust
use reqrio::*;
fn ff(){
    let headers = json::object! {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "Cookie": "__guid=15015764.1071255116101212729.1764940193317.2156; env_webp=1; _S=pvc5q7leemba50e4kn4qis4b95; QiHooGUID=4C8051464B2D97668E3B21198B9CA207.1766289287750; count=1; so-like-red=2; webp=1; so_huid=114r0SZFiQcJKtA38GZgwZg%2Fdit1cjUGuRcsIL2jTn4%2FE%3D; __huid=114r0SZFiQcJKtA38GZgwZg%2Fdit1cjUGuRcsIL2jTn4%2FE%3D; gtHuid=1",
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
    let mut req=ScReq::new()
        //设置最高HTTP版本，默认HTTP/1.1
        .with_alpn(ALPN::Http20)
        //Session内部默认不设置任何请求头，需要手动设置
        .with_header_json(headers).unwrap()
        //设置请求超时和尝试请求次数
        .with_timeout(Timeout::new_same(3000,3));
}
```
* GET的简单示例
```rust
use reqrio::*;

fn ff() {
    let mut req = ScReq::new();
    //get
    let mut res = req.get("https://www.baidu.com", None).unwrap();
    //获取相应头
    let header = res.header();
    //获取相应体，不移动所有权
    let body = res.decode_body().unwrap();
    //获取json，转移所有权
    let json = res.json().unwrap();

}
```

* 表单提交示例
```rust
use reqrio::*;
fn ff() {
    let mut req = ScReq::new();
    let url="https://www.baidu.com/api";
    let data=json::object! {
        "field1":"value1",
        "field2":"value2"
    };
    let resp=req.post(url,data.form()).unwrap();
}
```
* json提交示例
```rust
use reqrio::*;
fn ff() {
    let mut req = ScReq::new();
    let url="https://www.baidu.com/api";
    let data=json::object! {
        "field1":"value1",
        "field2":"value2"
    };
    let resp=req.post(url,data).unwrap();
}
```
* 提交已实现`Serialize`的struct示例

* 需要打开serde特性
```rust
use reqrio::*;
use serde::Serialize;
fn ff() {
    let mut req = ScReq::new();
    #[derive(Serialize)]
    struct Data{
        field1:String,
        field2:bool
    }
    let url="https://www.baidu.com/api";
    let resp=req.post(url,Body::json(&Data{field1:"value".to_string(),field2:false}).unwrap()).unwrap();
}
```

* Websocket示例
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