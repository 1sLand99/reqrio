use crate::*;

pub use proxy::Proxy;

pub use proxy::ProxyStream;

use crate::stream::kind::StreamKind;
use crate::Buffer;
#[cfg(feature = "aync")]
pub use async_stream::TlsStream;
pub use ws::{WebSocket, WebSocketBuilder};

#[cfg(feature = "aync")]
mod async_stream;

mod sync_stream;

#[cfg(feature = "aync")]
mod astream;
mod proxy;
mod kind;
mod ws;

pub struct TlsConfig<'a> {
    pub sni: &'a str,
    pub alpn: &'a ALPN,
    pub fingerprint: &'a mut Fingerprint,
    pub certificate: &'a mut Vec<Certificate>,
    pub private_key: &'a RsaKey,
    pub verify: bool,
}

pub struct ConnParam<'a> {
    pub url: &'a Url,
    pub proxy: &'a Proxy,
    pub timeout: &'a Timeout,
    pub fingerprint: &'a mut Fingerprint,
    pub alpn: &'a ALPN,
    pub verify: bool,
}

pub struct Stream {
    alpn: ALPN,
    kind: StreamKind,
}

impl Stream {
    pub fn unconnection() -> Self {
        Stream {
            alpn: ALPN::None,
            kind: StreamKind::NonConnection,
        }
    }
    pub fn alpn(&self) -> &ALPN {
        &self.alpn
    }
}

#[cfg(feature = "aync")]
impl Stream {
    pub async fn async_connect(&mut self, param: ConnParam<'_>) -> HlsResult<()> {
        let alpn = self.kind.async_conn(param).await?;
        self.alpn = alpn;
        Ok(())
    }
    pub async fn async_read(&mut self, buffer: &mut Buffer) -> HlsResult<()> {
        self.kind.async_read(buffer).await
    }

    pub async fn async_write(&mut self, data: &[u8]) -> HlsResult<()> {
        self.kind.async_write(data).await
    }

    pub async fn async_shutdown(&mut self) -> HlsResult<()> {
        self.kind.async_shutdown().await
    }
}

impl Stream {
    pub fn sync_connect(&mut self, param: ConnParam) -> HlsResult<()> {
        let alpn = self.kind.sync_conn(param)?;
        self.alpn = alpn;
        Ok(())
    }
    pub fn sync_read(&mut self, buffer: &mut Buffer) -> HlsResult<()> {
        self.kind.sync_read(buffer)
    }

    pub fn sync_write(&mut self, data: &[u8]) -> HlsResult<()> {
        self.kind.sync_write(data)
    }

    pub fn sync_shutdown(&mut self) -> HlsResult<()> {
        self.kind.sync_shutdown()
    }
}

