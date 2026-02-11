use super::sync_stream::SyncStream;
use crate::error::HlsResult;
#[cfg(feature = "aync")]
use crate::stream::astream::AsyncTlsStream;
#[cfg(feature = "aync")]
use crate::stream::astream::{AsyncTcpStream, TimeoutRW};
use crate::stream::proxy::ProxyStream;
use crate::stream::ConnParam;
use crate::url::Protocol;
use crate::*;
use std::io::Write;

pub enum StreamKind {
    NonConnection,
    //同步
    SyncHttp(ProxyStream<std::net::TcpStream>),
    SyncHttps(SyncStream<ProxyStream<std::net::TcpStream>>),
    //异步
    #[cfg(feature = "aync")]
    AsyncHttp(AsyncTcpStream),
    #[cfg(feature = "aync")]
    AsyncHttps(AsyncTlsStream),
}

#[cfg(feature = "aync")]
impl StreamKind {
    pub async fn async_conn(&mut self, param: ConnParam<'_>) -> HlsResult<ALPN> {
        let _ = self.async_shutdown().await;
        let stream = tokio::time::timeout(param.timeout.connect(), ProxyStream::async_connect(param.proxy, param.url.addr())).await??;
        match param.url.protocol() {
            Protocol::Http | Protocol::Ws => {
                *self = StreamKind::AsyncHttp(AsyncTcpStream::from_proxy_stream(stream, param.timeout));
                Ok(ALPN::Http11)
            }
            Protocol::Https | Protocol::Wss => {
                let tls_stream = AsyncTlsStream::connect_timeout(param, stream).await?;
                let alpn = tls_stream.alpn().map(|x| ALPN::from_slice(x.as_bytes())).unwrap_or(ALPN::Http11);
                *self = StreamKind::AsyncHttps(tls_stream);
                Ok(alpn)
            }
            _ => Err("stream not supported".into())
        }
    }


    pub async fn async_write(&mut self, buf: &[u8]) -> HlsResult<()> {
        match self {
            StreamKind::AsyncHttp(s) => {
                s.write(buf).await?;
                s.flush().await?;
                Ok(())
            }
            StreamKind::AsyncHttps(s) => {
                s.write(buf).await?;
                s.flush().await?;
                Ok(())
            }
            _ => Err("Unsupported async write".into()),
        }
    }

    pub async fn async_read(&mut self, buffer: &mut Buffer) -> HlsResult<()> {
        match self {
            StreamKind::AsyncHttp(s) => s.read(buffer).await,
            StreamKind::AsyncHttps(s) => Ok(s.read(buffer).await?),
            _ => Err("Unsupported async read".into()),
        }
    }

    pub async fn async_shutdown(&mut self) -> HlsResult<()> {
        match self {
            StreamKind::AsyncHttp(s) => Ok(s.shutdown().await?),
            StreamKind::AsyncHttps(s) => Ok(s.shutdown().await?),
            _ => Err("Unsupported async read".into()),
        }
    }
}

impl StreamKind {
    pub fn sync_conn(&mut self, param: ConnParam) -> HlsResult<ALPN> {
        let _ = self.sync_shutdown();
        let stream = ProxyStream::sync_connect(param.proxy, param.url.addr(), param.timeout)?; //param.proxy.create_sync_stream(param.url.addr(), param.timeout)?;
        match param.url.protocol() {
            Protocol::Http | Protocol::Ws => {
                *self = StreamKind::SyncHttp(stream);
                Ok(ALPN::Http11)
            }
            Protocol::Https | Protocol::Wss => {
                let tls_stream = SyncStream::connect(TlsConfig {
                    sni: param.url.addr().host(),
                    alpn: param.alpn,
                    fingerprint: param.fingerprint,
                    certificate: &mut vec![],
                    private_key: &RsaKey::none(),
                    verify: param.verify,
                }, stream)?;
                let alpn = tls_stream.alpn().map(|x| ALPN::from_slice(x.as_bytes())).unwrap_or(ALPN::Http11);
                *self = StreamKind::SyncHttps(tls_stream);
                Ok(alpn)
            }
            _ => Err("stream not supported".into())
        }
    }

    pub fn sync_write(&mut self, buf: &[u8]) -> HlsResult<()> {
        match self {
            StreamKind::SyncHttp(s) => {
                s.write_all(buf)?;
                Ok(())
            }
            StreamKind::SyncHttps(s) => {
                s.write_all(buf)?;
                Ok(())
            }
            _ => Err("Unsupported sync write".into()),
        }
    }

    pub fn sync_read(&mut self, buffer: &mut Buffer) -> HlsResult<()> {
        match self {
            StreamKind::SyncHttp(s) => buffer.sync_read(s),
            StreamKind::SyncHttps(s) => buffer.sync_read(s),
            _ => Err("Unsupported async read".into()),
        }
    }

    pub fn sync_shutdown(&mut self) -> HlsResult<()> {
        match self {
            StreamKind::SyncHttp(s) => Ok(s.shutdown()?),
            StreamKind::SyncHttps(s) => Ok(s.shutdown()?),
            _ => Err("Unsupported async read".into()),
        }
    }
}