mod sync_stream;

mod proxy;
mod ws;
#[cfg(feature = "aync")]
mod aync;
#[cfg(feature = "quic")]
mod quic;
#[cfg(feature = "quic")]
mod http3;
mod http2;
mod http1;

use crate::packet::HeaderParam;
use crate::*;
#[cfg(feature = "aync")]
pub use aync::TlsStreamA;
#[cfg(feature = "aync")]
use aync::{TcpStreamA, TimeoutRW, TlsStreamT};
use http1::HTTP1StreamS;
#[cfg(feature = "aync")]
use http1::HTTP1StreamA;
#[cfg(feature = "aync")]
use http2::HTTP2StreamA;
use http2::HTTP2StreamS;
#[cfg(feature = "quic")]
pub use http3::HTTP3StreamS;
pub use proxy::Proxy;
pub use proxy::ProxyStream;
#[cfg(feature = "quic")]
pub use quic::QUICStreamS;
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::{env, io};
pub use sync_stream::TlsStreamS;
pub use ws::{WebSocket, WebSocketBuilder};
#[cfg(all(feature = "quic", feature = "aync"))]
use crate::stream::http3::HTTP3StreamA;

pub struct ConnParam<'a> {
    pub url: &'a Url,
    pub proxy: &'a Proxy,
    pub timeout: &'a Timeout,
    pub fingerprint: &'a mut Fingerprint,
    pub alpn: &'a ALPN,
    pub verify: bool,
    pub cert: &'a mut Vec<Certificate>,
    pub key: &'a RsaKey,
    pub ca_cert: &'a Vec<Certificate>,
    pub key_log: &'a Option<PathBuf>,
    pub ech: bool,
    pub session: &'a Option<TlsSession>,
}

impl<'a, 'b: 'a> From<&'a mut ConnParam<'b>> for ClientConfig<'a> {
    fn from(param: &'a mut ConnParam<'b>) -> Self {
        ClientConfig {
            sni: param.url.sni(),
            alpn: param.alpn,
            fingerprint: param.fingerprint.tls_mut(),
            client_cert: param.cert,
            cert_key: param.key,
            verify: param.verify,
            ca_certs: param.ca_cert,
            key_log: param.key_log.clone().or_else(|| match env::var("SSLKEYLOGFILE") {
                Ok(key_log) => Some(Path::new(&key_log).to_path_buf()),
                Err(_) => None
            }),
            session: param.session,
        }
    }
}


pub enum HTTPStream {
    NonConnection,
    SyncH1(HTTP1StreamS),
    SyncH2(HTTP2StreamS),
    #[cfg(feature = "quic")]
    SyncH3(HTTP3StreamS),
    #[cfg(feature = "aync")]
    AsyncH1(HTTP1StreamA),
    #[cfg(feature = "aync")]
    AsyncH2(HTTP2StreamA),
    #[cfg(all(feature = "aync", feature = "quic"))]
    AsyncH3(HTTP3StreamA),
}

impl HTTPStream {
    pub fn scheme(&self) -> Option<Scheme> {
        match self {
            HTTPStream::NonConnection => None,
            HTTPStream::SyncH1(h1) => h1.stream().scheme(),
            HTTPStream::SyncH2(h2) => h2.stream().scheme(),
            #[cfg(feature = "quic")]
            HTTPStream::SyncH3(_) => Some(Scheme::Https),
            #[cfg(feature = "aync")]
            HTTPStream::AsyncH1(h1) => h1.stream().scheme(),
            #[cfg(feature = "aync")]
            HTTPStream::AsyncH2(h2) => h2.stream().scheme(),
            #[cfg(all(feature = "aync", feature = "quic"))]
            HTTPStream::AsyncH3(_) => Some(Scheme::Https),
        }
    }

    pub fn into_stream(self) -> HlsResult<Stream> {
        match self {
            HTTPStream::NonConnection => Err("connect first".into()),
            HTTPStream::SyncH1(h1) => Ok(h1.into_stream()),
            HTTPStream::SyncH2(h2) => Ok(h2.into_stream()),
            #[cfg(feature = "quic")]
            HTTPStream::SyncH3(_) => Err("use `QUICStreamS`".into()),
            #[cfg(feature = "aync")]
            HTTPStream::AsyncH1(h1) => Ok(h1.into_stream()),
            #[cfg(feature = "aync")]
            HTTPStream::AsyncH2(h2) => Ok(h2.into_stream()),
            #[cfg(all(feature = "aync", feature = "quic"))]
            HTTPStream::AsyncH3(_) => Err("use `HTTPStreamA`".into()),
        }
    }

    pub fn stream_mut(&mut self) -> HlsResult<&mut Stream> {
        match self {
            HTTPStream::NonConnection => Err("connect first".into()),
            HTTPStream::SyncH1(h1) => Ok(h1.stream_mut()),
            HTTPStream::SyncH2(h2) => Ok(h2.stream_mut()),
            #[cfg(feature = "quic")]
            HTTPStream::SyncH3(_) => Err("use `QUICStreamS`".into()),
            #[cfg(feature = "aync")]
            HTTPStream::AsyncH1(h1) => Ok(h1.stream_mut()),
            #[cfg(feature = "aync")]
            HTTPStream::AsyncH2(h2) => Ok(h2.stream_mut()),
            #[cfg(all(feature = "aync", feature = "quic"))]
            HTTPStream::AsyncH3(_) => Err("use `HTTPStreamA`".into()),
        }
    }
}


impl HTTPStream {
    pub fn send_sync(&mut self, header: &Header, body: &Body<'_>, param: HeaderParam) -> HlsResult<u64> {
        match self {
            HTTPStream::NonConnection => Err("need connected before send".into()),
            HTTPStream::SyncH1(h1) => h1.send(header, body, param),
            HTTPStream::SyncH2(h2) => h2.send(header, body, param),
            #[cfg(feature = "quic")]
            HTTPStream::SyncH3(h3) => h3.send(header, body, param),
            #[cfg(feature = "aync")]
            _ => Err("invalid sync stream".into()),
        }
    }

    pub fn recv_sync(&mut self, responses: &mut HashMap<u64, Response>) -> HlsResult<Vec<u64>> {
        match self {
            HTTPStream::NonConnection => Err("need connected before recv".into()),
            HTTPStream::SyncH1(h1) => h1.recv(responses),
            HTTPStream::SyncH2(h2) => h2.recv(responses),
            #[cfg(feature = "quic")]
            HTTPStream::SyncH3(h3) => h3.recv(responses),
            #[cfg(feature = "aync")]
            _ => Err("invalid sync stream".into()),
        }
    }

    pub fn conn_sync<'a, 'b: 'a>(&'a mut self, mut param: ConnParam<'b>) -> HlsResult<ALPN> {
        match param.alpn {
            #[cfg(feature = "quic")]
            ALPN::Http30 => {
                let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
                *self = HTTPStream::SyncH3(HTTP3StreamS::connect(socket, param)?);
                Ok(ALPN::Http30)
            }
            _ => {
                let mut stream = Stream::NonConnection;
                let alpn = stream.sync_conn(&mut param)?;
                *self = match alpn {
                    ALPN::Http20 => HTTPStream::SyncH2(HTTP2StreamS::new(stream, param.fingerprint)?),
                    _ => HTTPStream::SyncH1(HTTP1StreamS::new(stream)),
                };
                Ok(alpn)
            }
        }
    }

    #[allow(dead_code)]
    pub fn shutdown_sync(&mut self) -> HlsResult<()> {
        match self {
            HTTPStream::NonConnection => Err("need connected before send".into()),
            HTTPStream::SyncH1(h1) => h1.stream_mut().sync_shutdown(),
            HTTPStream::SyncH2(h2) => h2.stream_mut().sync_shutdown(),
            #[cfg(feature = "quic")]
            HTTPStream::SyncH3(h3) => h3.shutdown_sync(),
            #[cfg(feature = "aync")]
            _ => Err("invalid sync stream".into()),
        }
    }
}

#[cfg(feature = "aync")]
impl HTTPStream {
    pub async fn send_async(&mut self, header: &Header, body: &Body<'_>, param: HeaderParam<'_>) -> HlsResult<u64> {
        match self {
            HTTPStream::NonConnection => Err("need connected before send".into()),
            HTTPStream::AsyncH1(h1) => h1.send(header, body, param).await,
            HTTPStream::AsyncH2(h2) => h2.send(header, body, param).await,
            #[cfg(feature = "quic")]
            HTTPStream::AsyncH3(h3) => h3.send(header, body, param).await,
            _ => Err("invalid async stream".into()),
        }
    }

    pub async fn recv_async(&mut self, responses: &mut HashMap<u64, Response>) -> HlsResult<Vec<u64>> {
        match self {
            HTTPStream::NonConnection => Err("need connected before send".into()),
            HTTPStream::AsyncH1(h1) => h1.recv(responses).await,
            HTTPStream::AsyncH2(h2) => h2.recv(responses).await,
            #[cfg(feature = "quic")]
            HTTPStream::AsyncH3(h3) => h3.recv(responses).await,
            _ => Err("invalid async stream".into()),
        }
    }

    pub async fn conn_async<'a, 'b: 'a>(&'a mut self, mut param: ConnParam<'b>) -> HlsResult<ALPN> {
        match param.alpn {
            #[cfg(feature = "quic")]
            ALPN::Http30 => {
                let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
                *self = HTTPStream::AsyncH3(HTTP3StreamA::connect(socket, param).await?);
                Ok(ALPN::Http30)
            }
            _ => {
                let mut stream = Stream::NonConnection;
                let alpn = stream.async_conn(&mut param).await?;
                *self = match alpn {
                    ALPN::Http20 => HTTPStream::AsyncH2(HTTP2StreamA::new(stream, param.fingerprint).await?),
                    _ => HTTPStream::AsyncH1(HTTP1StreamA::new(stream)),
                };
                Ok(alpn)
            }
        }
    }
}

pub enum Stream {
    NonConnection,
    //同步
    SyncHttp(ProxyStream<std::net::TcpStream>),
    SyncHttps(TlsStreamS<ProxyStream<std::net::TcpStream>>),
    //异步
    #[cfg(feature = "aync")]
    AsyncHttp(TcpStreamA),
    #[cfg(feature = "aync")]
    AsyncHttps(TlsStreamT),
}

impl Stream {
    pub fn scheme(&self) -> Option<Scheme> {
        match self {
            Stream::NonConnection => None,
            Stream::SyncHttp(_) => Some(Scheme::Http),
            Stream::SyncHttps(_) => Some(Scheme::Https),
            #[cfg(feature = "aync")]
            Stream::AsyncHttp(_) => Some(Scheme::Http),
            #[cfg(feature = "aync")]
            Stream::AsyncHttps(_) => Some(Scheme::Https),
        }
    }

    pub fn tls_session(&self) -> Option<&TlsSession> {
        match self {
            Stream::SyncHttps(s) => Some(s.connection().session()),
            #[cfg(feature = "aync")]
            Stream::AsyncHttps(s) => Some(s.get_ref().connection().session()),
            _ => None
        }
    }
}

#[cfg(feature = "aync")]
impl Stream {
    pub async fn async_conn(&mut self, param: &mut ConnParam<'_>) -> HlsResult<ALPN> {
        let _ = self.async_shutdown().await;
        // let st = Time::now_mills();
        let connect = ProxyStream::async_connect(param.proxy, param.url.addr(), param.ech);
        let stream = tokio::time::timeout(param.timeout.connect(), connect).await??;
        // println!("TCP TIME: {}", Time::now_mills() - st);
        match param.url.scheme() {
            Scheme::Http | Scheme::Ws => {
                *self = Stream::AsyncHttp(TcpStreamA::from_proxy_stream(stream, param.timeout));
                Ok(ALPN::Http11)
            }
            Scheme::Https | Scheme::Wss => {
                // let st = Time::now_mills();
                let tls_stream = TlsStreamT::connect_timeout(param, stream).await?;
                // println!("TLS TIME: {}", Time::now_mills() - st);
                let alpn = tls_stream.alpn().cloned().unwrap_or(ALPN::Http11);
                *self = Stream::AsyncHttps(tls_stream);
                Ok(alpn)
            }
            _ => Err("stream not supported".into())
        }
    }


    pub async fn async_write(&mut self, buf: &[u8]) -> HlsResult<()> {
        match self {
            Stream::AsyncHttp(s) => s.write_all(buf).await,
            Stream::AsyncHttps(s) => s.write_all(buf).await,
            _ => Err("Unsupported async write".into()),
        }
    }

    pub async fn async_read(&mut self, buffer: &mut Buffer) -> HlsResult<()> {
        match self {
            Stream::AsyncHttp(s) => s.read(buffer).await,
            Stream::AsyncHttps(s) => Ok(s.read(buffer).await?),
            _ => Err("Unsupported async read".into()),
        }
    }

    pub async fn async_shutdown(&mut self) -> HlsResult<()> {
        match self {
            Stream::AsyncHttp(s) => Ok(s.shutdown().await?),
            Stream::AsyncHttps(s) => Ok(s.shutdown().await?),
            _ => Err("Unsupported async read".into()),
        }
    }
}

impl Stream {
    pub fn sync_conn<'a, 'b: 'a>(&'a mut self, param: &'a mut ConnParam<'b>) -> HlsResult<ALPN> {
        let _ = self.sync_shutdown();
        let stream = ProxyStream::sync_connect(param.proxy, param.url.addr(), param.timeout, param.ech)?;
        match param.url.scheme() {
            Scheme::Http | Scheme::Ws => {
                *self = Stream::SyncHttp(stream);
                Ok(ALPN::Http11)
            }
            Scheme::Https | Scheme::Wss => {
                let tls_stream = TlsStreamS::connect(ClientConfig::from(param), stream)?;
                let alpn = tls_stream.alpn().cloned().unwrap_or(ALPN::Http11);
                *self = Stream::SyncHttps(tls_stream);
                Ok(alpn)
            }
            _ => Err("stream not supported".into())
        }
    }

    pub fn sync_write(&mut self, buf: &[u8]) -> HlsResult<()> {
        match self {
            Stream::SyncHttp(s) => {
                s.write_all(buf)?;
                Ok(())
            }
            Stream::SyncHttps(s) => {
                s.write_all(buf)?;
                Ok(())
            }
            _ => Err("Unsupported sync write".into()),
        }
    }

    pub fn sync_read(&mut self, buffer: &mut Buffer) -> HlsResult<()> {
        match self {
            Stream::SyncHttp(stream) => {
                let len = io::Read::read(stream, buffer.unfilled())?;
                if len == 0 { return Err(HlsError::PeerClosedConnection); }
                buffer.add_len(len);
                Ok(())
            }
            Stream::SyncHttps(stream) => {
                let len = io::Read::read(stream, buffer.unfilled())?;
                if len == 0 { return Err(HlsError::PeerClosedConnection); }
                buffer.add_len(len);
                Ok(())
            }
            _ => Err("Unsupported async read".into()),
        }
    }

    pub fn sync_shutdown(&mut self) -> HlsResult<()> {
        match self {
            Stream::SyncHttp(s) => Ok(s.shutdown()?),
            Stream::SyncHttps(s) => Ok(s.shutdown()?),
            _ => Err("Unsupported async read".into()),
        }
    }
}


