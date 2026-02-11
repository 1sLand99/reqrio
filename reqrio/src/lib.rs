//! #### `reqrio` is an HTTP request library designed to enable quick, simple, and convenient use of HTTP requests.
//! * reqrio features: low copying, high concurrency, low overhead
//! * Reqrio supports TLS fingerprinting, which can be set via hexadecimal or Ja3 data from the TLS handshake. Only cls_sync and cls_async are supported (**subscription only**).
//! * By default, reqrio will reorder the request headers in the same way as the browser (it will reorder the request headers).
//! * CLS mode uses BoringSSL, consistent with browsers such as Chrome and Edge.
//!
//! #### By default, reqrio does not enable HTTP requests; it is only exported as an HTTP data stream parsing library. Requests require features to be enabled.
//! * `std_sync`: Standard TLS library ([rustls](https://github.com/rustls/rustls), synchronous requests)
//! * `std_async`: Standard TLS library ([tokio-rustls](https://github.com/rustls/tokio-rustls), asynchronous requests)
//! * `cls_sync`: Self-developed TLS library (**Algorithm is imperfect, does not verify server certificates, do not use in production mode**) [reqtls](https://github.com/xllgl2017/reqrio/tree/master/reqtls), synchronous requests
//! * `cls_async`: Self-developed TLS library (**Algorithm is imperfect, does not verify server certificates, do not use in production mode**) [reqtls](https://github.com/xllgl2017/reqrio/tree/master/reqtls), asynchronous requests
//!
//! **Note:** std and cls cannot exist simultaneously, while sync and async can exist simultaneously.
//!
//! ### Usage examples (supports Rust, Python, and Java):
//!
//! * Rust HTTP Example
//!
//! ```rust
//! use reqrio::{Fingerprint, ScReq, ALPN};
//!
//! fn ff() {
//!     let fingerprint = Fingerprint::default().unwrap();
//!     fingerprint.set_ja3("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,13-11-65037-17613-45-18-16-5-43-10-0-27-23-35-51-65281,4588-29-23-24,0");
//!     let req = ScReq::new()
//!         //The default is to use http/1.1
//!         .with_alpn(ALPN::Http20)
//!         .with_fingerprint(fingerprint)
//!         .with_url("https://www.baidu.com").unwrap();
//!     let headers = json::object! {
//!         "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
//!         "Accept-Encoding": "gzip, deflate, br, zstd",
//!         "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
//!         "Cache-Control": "no-cache",
//!         "Connection": "keep-alive",
//!         "Cookie": "__guid=15015764.1071255116101212729.1764940193317.2156; env_webp=1; _S=pvc5q7leemba50e4kn4qis4b95; QiHooGUID=4C8051464B2D97668E3B21198B9CA207.1766289287750; count=1; so-like-red=2; webp=1; so_huid=114r0SZFiQcJKtA38GZgwZg%2Fdit1cjUGuRcsIL2jTn4%2FE%3D; __huid=114r0SZFiQcJKtA38GZgwZg%2Fdit1cjUGuRcsIL2jTn4%2FE%3D; gtHuid=1",
//!         "Host": "m.so.com",
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
//!     //By default, there are no request headers; you need to configure them yourself.
//!     req.set_headers_json(header);
//!     let res = req.get().unwrap();
//!     //Get response headers
//!     let header = res.header();
//!     //Get the response body; the body here has already been decoded.
//!     let body = res.decode_body().unwrap();
//!     //Try decoding to JSON
//!     let json = res.json().unwrap();
//! }
//! ```
//!
//! * Rust WebSocket Example
//! ```rust
//! use reqrio::*;
//!
//! fn ff() {
//!     let mut ws = WebSocket::sync_build()
//!         .with_url("wss://poe.game.qq.com/").unwrap()
//!         .with_uri("wss://poe.game.qq.com/api/trade2/live/poe2/%E7%93%A6%E5%B0%94%E7%9A%84%E5%AE%BF%E5%91%BD/32Y6Wjkc5").unwrap()
//!         .with_origin("https://poe.game.qq.com").unwrap()
//!         .with_cookie("pac_uid=0_NattYaCs7NNmH; omgid=0_NattYaCs7NNmH; _qimei_uuid42=19c1f11150d1000f92fe16d850a9c40cf94ef1d39f; _qimei_fingerprint=f3dc39297e432b1f08da57e9904a8f52; _qimei_q36=; _qimei_h38=a549811f92fe16d850a9c40c02000006b19c1f; _qpsvr_localtk=0.2296543129537577; RK=WPZCq/wl3I; ptcz=c338dead622f05f0d8467ac10589e7e45326b81d67ff476b9643f933cfdc644a; eas_sid=M1b7q677w9D5R5P2L8x5g4p313; eas_entry=https%3A%2F%2Fgraph.qq.com%2F; POESESSID=939e23af876572a0b2852b2e183e20cc").unwrap()
//!         .with_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0").unwrap()
//!         .build().unwrap();
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

use crate::error::HlsResult;
#[cfg(feature = "aync")]
pub use acq::AcReq;
pub use alpn::ALPN;
pub use body::BodyType;
pub use buffer::Buffer;
pub use error::HlsError;
pub use ext::{ReqExt, ReqGenExt};
pub use fingerprint::Fingerprint;
pub use packet::{
    Application, Body, ContentType, Cookie, Font, FrameFlag, FrameType, H2Frame, Header, HeaderKey,
    HeaderValue, HttpStatus, Method, Response, Text, WsFrame, WsOpcode,
};
pub use reqrio_json as json;
pub use reqtls::*;
pub use scq::ScReq;
pub use stream::{ProxyStream, WebSocket, WebSocketBuilder, Proxy};
#[cfg(feature = "aync")]
pub use stream::TlsStream;
pub use stream::TlsConfig;
pub use timeout::Timeout;
#[cfg(feature = "tokio")]
pub use tokio;
pub use url::{Addr, Protocol, Uri, Url, Param};

pub type ReqCallback = Box<dyn FnMut(&[u8]) -> HlsResult<()>>;
pub const HTTP_GAP: &[u8; 4] = b"\r\n\r\n";
pub const CHUNK_END: [u8; 5] = [48, 13, 10, 13, 10];


#[cfg(feature = "aync")]
mod acq;
mod alpn;
mod buffer;
pub mod coder;
mod error;
#[cfg(feature = "export")]
mod export;
mod ext;
mod file;
mod packet;
mod scq;
mod stream;
mod timeout;
mod url;
mod body;
mod fingerprint;
