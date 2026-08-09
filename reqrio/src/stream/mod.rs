mod sync_stream;

mod proxy;
mod ws;
#[cfg(feature = "aync")]
mod aync;
mod quic;
mod http3;
mod http2;
mod http1;

use crate::*;
#[cfg(feature = "aync")]
pub use aync::TlsStream;
#[cfg(feature = "aync")]
use aync::{TcpStreamA, TimeoutRW, TlsStreamA};
use http1::HTTP1StreamS;
use http2::HTTP2StreamS;
pub use http3::HTTP3StreamS;
pub use proxy::Proxy;
pub use proxy::ProxyStream;
pub use quic::QUICStreamS;
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::{env, io};
pub use sync_stream::SyncStream;
pub use ws::{WebSocket, WebSocketBuilder};

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
    SyncH3(HTTP3StreamS),
}


impl HTTPStream {
    pub fn send(&mut self, url: &Url, header: &Header, body: &Body<'_>, fingerprint: &Fingerprint) -> HlsResult<u64> {
        match self {
            HTTPStream::NonConnection => Err("need connected before send".into()),
            HTTPStream::SyncH1(h1) => h1.send(url, header, body, fingerprint),
            HTTPStream::SyncH2(h2) => h2.send(url, header, body, fingerprint),
            HTTPStream::SyncH3(h3) => h3.send(url, header, body, fingerprint),
        }
    }

    pub fn recv(&mut self, responses: &mut HashMap<u64, Response>) -> HlsResult<Vec<u64>> {
        match self {
            HTTPStream::NonConnection => Err("need connected before recv".into()),
            HTTPStream::SyncH1(h1) => h1.recv(responses),
            HTTPStream::SyncH2(h2) => h2.recv(responses),
            HTTPStream::SyncH3(h3) => h3.recv(responses),
        }
    }


    pub fn sync_conn<'a, 'b: 'a>(&'a mut self, mut param: ConnParam<'b>) -> HlsResult<ALPN> {
        match param.alpn {
            ALPN::Http30 => {
                *self = HTTPStream::SyncH3(HTTP3StreamS::connect(param)?);
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

    pub fn scheme(&self) -> Option<Scheme> {
        match self {
            HTTPStream::NonConnection => None,
            HTTPStream::SyncH1(h1) => h1.stream().scheme(),
            HTTPStream::SyncH2(h2) => h2.stream().scheme(),
            HTTPStream::SyncH3(_) => Some(Scheme::Https),
        }
    }
}

pub enum Stream {
    NonConnection,
    //同步
    SyncHttp(ProxyStream<std::net::TcpStream>),
    SyncHttps(SyncStream<ProxyStream<std::net::TcpStream>>),
    //异步
    #[cfg(feature = "aync")]
    AsyncHttp(TcpStreamA),
    #[cfg(feature = "aync")]
    AsyncHttps(TlsStreamA),
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
    pub async fn async_conn(&mut self, mut param: ConnParam<'_>) -> HlsResult<ALPN> {
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
                let tls_stream = TlsStreamA::connect_timeout(&mut param, stream).await?;
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
                let tls_stream = SyncStream::connect(ClientConfig::from(param), stream)?;
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


