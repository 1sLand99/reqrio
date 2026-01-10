//! #### reqrio是http请求库，目标是可以快速、简单、便捷使用http请求
//! * reqrio特性: 低拷贝、高并发、低损耗
//! * reqrio支持tls指纹，可以通过tls握手的十六进制或ja3设置,仅cls_sync和cls_async支持(**仅订阅**),
//! * reqrio默认对请求头的顺序会默认和浏览器一致(会对请求头进行重排序)
//! * cls模式使用boringssl，和浏览器chrome、edge等一致。
//!
//! #### reqrio默认不开启http请求，仅作为http数据数据流解析库导出，请求需要打开features
//! * std_sync: 标准的tls库([rustls](https://github.com/rustls/rustls)，同步请求
//! * std_async: 标准的tls库([tokio-rustls](https://github.com/rustls/tokio-rustls))，异步请求
//! * cls_sync: 自研tls库(**算法不完善，不校验服务端证书，请勿用于生产模式**)[reqtls](https://github.com/xllgl2017/reqrio/tree/master/reqtls), 同步请求
//! * cls_async: 自研tls库(**算法不完善，不校验服务端证书，请勿用于生产模式**)[reqtls](https://github.com/xllgl2017/reqrio/tree/master/reqtls), 异步请求
//!
//! **注意**: std和cls不可以同时存在，sync和async可以同时存在
//!
//! ### 使用示例(feaures=cls_sync)
//! * 快速请求
//! ```rust
//! use reqrio::ScReq;
//! let req=ScReq::new_with_url("https://www.baidu.com").unwrap();
//! ```
//! * 详细用法:
//! ```rust
//! use reqrio::{Fingerprint, ScReq, ALPN};
//! let fingerprint=Fingerprint::default().unwrap();
//! fingerprint.set_ja3("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,13-11-65037-17613-45-18-16-5-43-10-0-27-23-35-51-65281,4588-29-23-24,0");
//! let req=ScReq::new()
//!     //默认使用http/1.1
//!     .with_alpn(ALPN::Http20)
//!     .with_fingerprint(fingerprint)
//!     .with_url("https://www.baidu.com").unwrap();
//! let headers = json::object! {
//!     "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
//!     "Accept-Encoding": "gzip, deflate, br, zstd",
//!     "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
//!     "Cache-Control": "no-cache",
//!     "Connection": "keep-alive",
//!     "Cookie": "__guid=15015764.1071255116101212729.1764940193317.2156; env_webp=1; _S=pvc5q7leemba50e4kn4qis4b95; QiHooGUID=4C8051464B2D97668E3B21198B9CA207.1766289287750; count=1; so-like-red=2; webp=1; so_huid=114r0SZFiQcJKtA38GZgwZg%2Fdit1cjUGuRcsIL2jTn4%2FE%3D; __huid=114r0SZFiQcJKtA38GZgwZg%2Fdit1cjUGuRcsIL2jTn4%2FE%3D; gtHuid=1",
//!     "Host": "m.so.com",
//!     "Pragma": "no-cache",
//!     "Sec-Fetch-Dest": "document",
//!     "Sec-Fetch-Mode": "navigate",
//!     "Sec-Fetch-Site": "none",
//!     "Sec-Fetch-User": "?1",
//!     "Upgrade-Insecure-Requests": 1,
//!     "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0",
//!     "sec-ch-ua": r#""Microsoft Edge";v="143", "Chromium";v="143", "Not A(Brand";v="24""#,
//!     "sec-ch-ua-mobile": "?0",
//!     "sec-ch-ua-platform": r#""Windows""#
//! };
//! //默认没有任何请求头，需要自己设置
//! req.set_headers_json(header);
//! let mut len = Rc::new(RefCell::new(0));
//! //这里设置回调函数
//! req.set_callback(move|bs|{
//!     *len.borrow_mut() += bs.len();
//!     println!("{}",bs.len());
//! })
//! let res=req.get().unwrap();
//! //获取响应头
//! let header=res.header();
//! //获取响应体,这里的body已经解编码
//! let body=res.decode_body().unwrap();
//! //尝试解码到json
//! let json=res.to_json().unwrap();
//! ```
//! * websocket示例:
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
//!
//!

#[cfg(aync)]
pub use acq::AcReq;
pub use alpn::ALPN;
pub use buffer::Buffer;
pub use ext::{ReqExt, ReqGenExt};
pub use reqrio_json as json;
pub use packet::{
    Application, Body, ContentType, Cookie, Font, Frame, FrameFlag, FrameType, Header, HeaderValue,
    HttpStatus, Method, Response, Text, HeaderKey, WsFrame, WsOpcode,
};
#[cfg(use_cls)]
pub use reqtls::Fingerprint;
#[cfg(sync)]
pub use scq::ScReq;
pub use body::BodyType;
pub use stream::Proxy;
#[cfg(feature = "cls_async")]
pub use stream::{TlsStream, TlsConnector};
#[cfg(anys)]
pub use stream::{WebSocket, WebSocketBuilder};
#[cfg(feature = "tokio")]
pub use tokio;
pub use url::{Addr, Protocol, Uri, Url};
pub use error::HlsError;
#[cfg(anys)]
use crate::error::HlsResult;
pub use timeout::Timeout;

#[cfg(anys)]
pub type ReqCallback = Box<dyn FnMut(&[u8]) -> HlsResult<()>>;


#[cfg(aync)]
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
#[cfg(sync)]
mod scq;
mod stream;
mod timeout;
mod url;
mod body;
