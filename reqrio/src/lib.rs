//!# reqrio is an HTTP request library designed for fast, simple, and convenient HTTP request usage.
//!
//! * Features: Low copy, high concurrency, low overhead
//!
//! * Supports TLS fingerprinting, which can be configured via hexadecimal, Ja3, or Ja4 TLS handshake settings (**subscription only**).
//!
//! * Ensures **request header order** (see [Request Header Order Table](#request-header-order-table)), consistent with browsers.
//!
//! * Uses **BoringSSL** to implement TLS, consistent with browsers like Chrome and Edge.
//!
//! ### Low-Copy
//!
//! `reqrio` is a low copy request sending engine used to efficiently encrypt user or file data over TLS and send it to TCP. `reqrio`
//! Convert user input data such as form data, json, bytes, text, etc. into bytes for storage, and only copy once during TLS encryption, while only the data is processed in other stages
//! Borrow (borrowing). File uploads are read through into_deader to reduce memory overhead
//!
//! ```text
//!
//!         Form  ┌────────┐encode->bytes ┌──────────┐             ┌──────────┐
//!  User ───────►│        │─────────────►│          │             │          │
//!         Json  │ ScReq  │  into_bytes  │  Request │ copy slice  │ fragment │ write ┌───────┐
//!               │ AcReq  │              │  borrow  │────────────►│  TLS     │──────►│  TCP  │
//!        Files  │(Engine)│ into_reader  │  reader  │             │ Encrypt  │       └───────┘
//!  User ───────►│        │─────────────►│          │             │          │
//!               └────────┘              └──────────┘             └──────────┘
//! ```
//!
//! ### Request Header Order Table
//!
//! | No. | HTTP/2.0                    | HTTP/1.1                  |
//! |:----|:----------------------------|:--------------------------|
//! | 1   | cache-control               | Host                      |
//! | 2   | sec-ch-ua                   | Connection                |
//! | 3   | sec-ch-ua-mobile            | Content-Length            |
//! | 4   | sec-ch-ua-full-version      | Authorization             |
//! | 5   | sec-ch-ua-arch              | Content-Type              |
//! | 6   | sec-ch-ua-platform          | Cache-Control             |
//! | 7   | sec-ch-ua-platform-version  | sec-ch-ua                 |
//! | 8   | sec-ch-ua-model             | sec-ch-ua-mobile          |
//! | 9   | sec-ch-ua-bitness           | sec-ch-ua-platform        |
//! | 10  | sec-ch-ua-full-version-list | Upgrade-Insecure-Requests |
//! | 11  | upgrade-insecure-requests   | User-Agent                |
//! | 12  | user-agent                  | Accept                    |
//! | 13  | accept                      | Sec-Fetch-Site            |
//! | 14  | origin                      | Sec-Fetch-Mode            |
//! | 15  | sec-fetch-site              | Sec-Fetch-User            |
//! | 16  | sec-fetch-mode              | Sec-Fetch-Dest            |
//! | 17  | sec-fetch-user              | Sec-Fetch-Storage-Access  |
//! | 18  | sec-fetch-dest              | Referer                   |
//! | 19  | sec-fetch-storage-access    | Accept-Encoding           |
//! | 20  | referer                     | Accept-Language           |
//! | 21  | accept-encoding             | Cookie                    |
//! | 22  | accept-language             | Origin                    |
//! | 23  | cookie                      |                           |
//! | 24  | priority                    |                           |
//! |     | //unknown                   |                           |
//! | 25  | content-encoding            |                           |
//! | 26  | content-type                |                           |
//! | 27  | authorization               |                           |
//! | 28  | content-type                |                           |
//!
//! ## Quick start
//!
//! * Init Req
//! ```rust
//! # use reqrio::*;
//! # fn ff(){
//!     let headers = json::object! {
//!         "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
//!         "Accept-Encoding": "gzip, deflate, br, zstd",
//!         "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
//!         "Cache-Control": "no-cache",
//!         "Connection": "keep-alive",
//!         "Cookie": "__guid=15015764.1071255116101212729.1764940193317.2156; env_webp=1; _S=pvc5q7leemba50e4kn4qis4b95; QiHooGUID=4C8051464B2D97668E3B21198B9CA207.1766289287750; count=1; so-like-red=2; webp=1; so_huid=114r0SZFiQcJKtA38GZgwZg%2Fdit1cjUGuRcsIL2jTn4%2FE%3D; __huid=114r0SZFiQcJKtA38GZgwZg%2Fdit1cjUGuRcsIL2jTn4%2FE%3D; gtHuid=1",
//!         "Pragma": "no-cache",
//!         "Sec-Fetch-Dest": "document",
//!         "Sec-Fetch-Mode": "navigate",
//!         "Sec-Fetch-Site": "none",
//!         "Sec-Fetch-User": "?1",
//!         "Upgrade-Insecure-Requests": 1,
//!         "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0",
//!         "sec-ch-ua": r#""Microsoft Edge";v="143", "Chromium";v="143", "Not A(Brand";v="24""#,
//!         "sec-ch-ua-mobile": "?0",
//!         "sec-ch-ua-platform": r#""Windows""#
//!     };
//!     let mut req=ScReq::new()
//!         //The default is to use http/1.1
//!         .with_alpn(ALPN::Http20)
//!         //By default, there are no request headers; you need to configure them yourself.
//!         .with_header_json(headers).unwrap()
//!         //Set request timeout and number of attempts to request
//!         .with_timeout(Timeout::new_same(3000,3));
//! # }
//! ```
//! * Sample GET
//! ```rust
//! # use reqrio::*;
//!
//! # fn ff() {
//!     # let mut req = ScReq::new();
//!     let params=json::object! {
//!         "p1":1,
//!         "p2":"斯"
//!     };
//!     //get
//!     let mut res = req.get("https://www.baidu.com".params(params), None).unwrap();
//!     //Get response headers
//!     let header = res.header();
//!     //Get the response body; the body here has already been decoded.
//!     let body = res.decode_body().unwrap();
//!     //Try decoding to JSON
//!     let json = res.json().unwrap();
//!
//! # }
//! ```
//!
//! * Post with form data
//! ```rust
//! # use reqrio::*;
//! # fn ff() {
//!     # let mut req = ScReq::new();
//!     let url="https://www.baidu.com/api";
//!     let data=json::object! {
//!         "field1":"value1",
//!         "field2":"value2"
//!     };
//!     let resp=req.post(url,data.form()).unwrap();
//! # }
//! ```
//! * Post with json data
//! ```rust
//! # use reqrio::*;
//! # fn ff() {
//!     # let mut req = ScReq::new();
//!     let url="https://www.baidu.com/api";
//!     let data=json::object! {
//!         "field1":"value1",
//!         "field2":"value2"
//!     };
//!     let resp=req.post(url,data).unwrap();
//! # }
//! ```
//! Post with form/json data, which struct impl `Serialize`
//! ```rust
//! # use reqrio::*;
//! # use serde::Serialize;
//! # fn ff() {
//!     # let mut req = ScReq::new();
//!     #[derive(Serialize)]
//!     struct Data{
//!         field1:String,
//!         field2:bool
//!     }
//!     let url="https://www.baidu.com/api";
//!     let resp=req.post(url,Body::json(&Data{field1:"value".to_string(),field2:false}).unwrap()).unwrap();
//! # }
//! ```
//! ```rust
//! use reqrio::*;
//!
//! fn ff() {
//!     let url=Url::try_from("wss://poe.game.qq.com/wss://poe.game.qq.com/api/trade2/live/poe2/%E7%93%A6%E5%B0%94%E7%9A%84%E5%AE%BF%E5%91%BD/32Y6Wjkc5").unwrap();
//!     let mut ws = WebSocket::sync_build()
//!         .with_origin("https://poe.game.qq.com").unwrap()
//!         .with_cookie("pac_uid=0_NattYaCs7NNmH; omgid=0_NattYaCs7NNmH; _qimei_uuid42=19c1f11150d1000f92fe16d850a9c40cf94ef1d39f; _qimei_fingerprint=f3dc39297e432b1f08da57e9904a8f52; _qimei_q36=; _qimei_h38=a549811f92fe16d850a9c40c02000006b19c1f; _qpsvr_localtk=0.2296543129537577; RK=WPZCq/wl3I; ptcz=c338dead622f05f0d8467ac10589e7e45326b81d67ff476b9643f933cfdc644a; eas_sid=M1b7q677w9D5R5P2L8x5g4p313; eas_entry=https%3A%2F%2Fgraph.qq.com%2F; POESESSID=939e23af876572a0b2852b2e183e20cc").unwrap()
//!         .with_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0").unwrap()
//!         .build(&url).unwrap();
//!     loop {
//!         let res = ws.read_frame().unwrap();
//!         match res.frame_type().op_code() {
//!             WsOpcode::CONTINUATION => {}
//!             WsOpcode::TEXT => println!("{}", res.payload().as_bytes().len()),
//!             WsOpcode::BINARY => {}
//!             WsOpcode::CLOSE => {}
//!             WsOpcode::PING => {
//!                 println!("PING");
//!                 let pong = WsFrame::new_pong(true, res.payload().as_bytes());
//!                 ws.write_frame(pong).unwrap();
//!             }
//!             WsOpcode::PONG => {}
//!         }
//!     }
//! }
//! ```

#[cfg(feature = "aync")]
mod acq;
mod buffer;
pub mod hpack;
mod error;
#[cfg(feature = "export")]
mod export;
mod ext;
mod form_data;
mod packet;
mod scq;
mod stream;
mod body;
mod fingerprint;
// mod huffman;
mod reader;
mod request;
mod cookie;
mod time;

pub type ReqCallback = Box<dyn FnMut(&[u8]) -> HlsResult<()>>;
pub const HTTP_GAP: &[u8; 4] = b"\r\n\r\n";
pub const CHUNK_END: [u8; 7] = [13, 10, 48, 13, 10, 13, 10];

use crate::error::HlsResult;
#[cfg(feature = "aync")]
pub use acq::AcReq;
pub use body::{Body, BodyData, BodyExt};
pub use buffer::Buffer;
pub use error::HlsError;
pub use ext::{ReqExt, ReqGenExt, UrlExt};
pub use fingerprint::{Fingerprint, H2Finger};
pub use form_data::{FileForm, HttpFile};
pub use packet::{
    Application, ContentType, Cookie, Font, FrameFlag, FrameType, H2Frame, H2Setting, Header,
    HeaderKey, HeaderValue, HttpStatus, Method, Response, Text, WsFrame, WsOpcode,
};
pub use reqrio_json as json;
pub use reqtls::*;
pub use scq::ScReq;
#[cfg(feature = "aync")]
pub use stream::TlsStream;
pub use stream::{ClientConfig, Proxy, ProxyStream, ServerConfig, SyncStream, WebSocket, WebSocketBuilder};
pub use time::{Time, Timeout, TimeError};
#[cfg(feature = "tokio")]
pub use tokio;


