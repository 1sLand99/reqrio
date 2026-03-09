//!### reqrio is an HTTP request library designed for fast, simple, and convenient HTTP request usage.                                                                          
//!                                                                                                                                                                              
//! * Features: Low copy, high concurrency, low overhead                                                                                                                         
//!                                                                                                                                                                              
//! * Supports TLS fingerprinting, which can be configured via hexadecimal, Ja3, or Ja4 TLS handshake settings (**subscription only**).                                          
//!                                                                                                                                                                              
//! * Ensures **request header order** (see [Request Header Order Table](#request-header-order-table)), consistent with browsers.                                                
//!                                                                                                                                                                              
//! * Uses **BoringSSL** to implement TLS, consistent with browsers like Chrome and Edge.                                                                                        
//!                                                                                                                                                                              
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
//! * Rust HTTP Example
//!
//! ```rust
//! use reqrio::*;
//!
//! fn ff() {
//!     let mut req = ScReq::new()
//!         //The default is to use http/1.1
//!         .with_alpn(ALPN::Http20)
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
//!     req.set_headers_json(headers);
//!     let mut res = req.get().unwrap();
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
pub use stream::{ProxyStream, WebSocket, WebSocketBuilder, Proxy, ServerConfig, ClientConfig, SyncStream};
#[cfg(feature = "aync")]
pub use stream::TlsStream;
pub use timeout::Timeout;
#[cfg(feature = "tokio")]
pub use tokio;
pub use form_data::{HttpFile, FileForm};

pub type ReqCallback = Box<dyn FnMut(&[u8]) -> HlsResult<()>>;
pub const HTTP_GAP: &[u8; 4] = b"\r\n\r\n";
pub const CHUNK_END: [u8; 7] = [13, 10, 48, 13, 10, 13, 10];

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
mod timeout;
mod body;
mod fingerprint;
mod huffman;
mod reader;
mod request;
