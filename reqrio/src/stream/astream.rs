#[cfg(cls_async)]
use super::async_stream::TlsStream;
use crate::error::HlsResult;
use crate::stream::proxy::ProxyStream;
use crate::stream::ConnParam;
use crate::*;
use reqtls::RsaKey;
#[cfg(all(feature = "std_async", not(feature = "cls_sync")))]
use rustls::pki_types::{DnsName, ServerName};
#[cfg(all(feature = "std_async", not(feature = "cls_sync")))]
use rustls::{ClientConfig, RootCertStore};
#[cfg(all(feature = "std_async", not(feature = "cls_sync")))]
use std::sync::Arc;
use std::time::Duration;
use tokio::io;
#[cfg(any(feature = "cls_async", feature = "std_async"))]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(any(feature = "cls_async", feature = "std_async"))]
use tokio::net::TcpStream;
#[cfg(all(feature = "std_async", not(feature = "cls_sync")))]
use tokio_rustls::client::TlsStream;
#[cfg(all(feature = "std_async", not(feature = "cls_sync")))]
use tokio_rustls::TlsConnector;

pub trait TimeoutRW<S: AsyncReadExt + AsyncWriteExt + Unpin> {
    fn stream(&mut self) -> &mut S;
    fn read_timeout(&self) -> Option<Duration>;
    fn write_timeout(&self) -> Option<Duration>;

    async fn read(&mut self, buffer: &mut Buffer) -> HlsResult<()> {
        match self.read_timeout() {
            None => buffer.async_read(self.stream()).await,
            Some(timeout) => tokio::time::timeout(timeout, buffer.async_read(self.stream())).await?
        }
    }

    async fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.write_timeout() {
            None => self.stream().write(buf).await,
            Some(timeout) => tokio::time::timeout(timeout, self.stream().write(buf)).await?
        }
    }

    async fn flush(&mut self) -> io::Result<()> {
        match self.write_timeout() {
            None => self.stream().flush().await,
            Some(timeout) => tokio::time::timeout(timeout, self.stream().flush()).await?
        }
    }

    async fn shutdown(&mut self) -> HlsResult<()> {
        match self.write_timeout() {
            None => self.stream().shutdown().await?,
            Some(timeout) => tokio::time::timeout(timeout, self.stream().shutdown()).await??
        }
        Ok(())
    }
}

#[cfg(any(feature = "cls_async", feature = "std_async"))]
pub struct AsyncTcpStream {
    stream: ProxyStream<TcpStream>,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
}

#[cfg(any(feature = "cls_async", feature = "std_async"))]
impl AsyncTcpStream {
    pub fn from_proxy_stream(stream: ProxyStream<TcpStream>, timeout: &Timeout) -> Self {
        AsyncTcpStream {
            stream,
            read_timeout: Option::from(timeout.read()),
            write_timeout: Option::from(timeout.write()),
        }
    }
}

impl TimeoutRW<ProxyStream<TcpStream>> for AsyncTcpStream {
    fn stream(&mut self) -> &mut ProxyStream<TcpStream> {
        &mut self.stream
    }

    fn read_timeout(&self) -> Option<Duration> {
        self.read_timeout
    }

    fn write_timeout(&self) -> Option<Duration> {
        self.write_timeout
    }
}

#[cfg(std_async)]
pub struct StdAsyncTlsStream {
    stream: TlsStream<ProxyStream<TcpStream>>,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
}

#[cfg(std_async)]
impl StdAsyncTlsStream {
    pub async fn connect_timeout(param: ConnParam<'_>, tcp: ProxyStream<TcpStream>) -> HlsResult<StdAsyncTlsStream> {
        let dns_name = DnsName::try_from(param.url.addr().host().to_string())?;
        let server_name = ServerName::DnsName(dns_name);
        let mut root = RootCertStore::empty();
        root.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut config = ClientConfig::builder()
            .with_root_certificates(root)
            .with_no_client_auth();
        if let ALPN::Http20 = param.alpn {
            println!("111");
            config.alpn_protocols = vec![
                ALPN::Http20.value(),
                ALPN::Http11.value(),
                ALPN::Http10.value(),
            ]
        }
        let connector = TlsConnector::from(Arc::new(config));
        let stream = tokio::time::timeout(param.timeout.connect(), connector.connect(server_name, tcp)).await??;
        Ok(StdAsyncTlsStream {
            stream,
            read_timeout: Some(param.timeout.read()),
            write_timeout: Some(param.timeout.write()),
        })
    }


    pub fn alpn(&self) -> Option<ALPN> {
        let alpn = self.stream.get_ref().1.alpn_protocol()?;
        Some(ALPN::from_slice(alpn))
    }
}

#[cfg(std_async)]
impl TimeoutRW<TlsStream<ProxyStream<TcpStream>>> for StdAsyncTlsStream {
    fn stream(&mut self) -> &mut TlsStream<ProxyStream<TcpStream>> {
        &mut self.stream
    }

    fn read_timeout(&self) -> Option<Duration> {
        self.read_timeout
    }

    fn write_timeout(&self) -> Option<Duration> {
        self.write_timeout
    }
}


#[cfg(cls_async)]
pub struct AsyncTlsStream {
    stream: TlsStream<ProxyStream<TcpStream>>,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
}

#[cfg(cls_async)]
impl AsyncTlsStream {
    pub async fn connect_timeout(param: ConnParam<'_>, tcp: ProxyStream<TcpStream>) -> HlsResult<AsyncTlsStream> {
        let connect_timeout = param.timeout.connect();
        let read_timeout = param.timeout.read();
        let write_timeout = param.timeout.write();
        let config = TlsConfig {
            sni: param.url.addr().host(),
            alpn: param.alpn,
            fingerprint: param.fingerprint,
            certificate: &mut vec![],
            private_key: &RsaKey::none(),
            verify: param.verify,
        };
        let stream = TlsStream::connect(tcp, config);
        Ok(AsyncTlsStream {
            stream: tokio::time::timeout(connect_timeout, stream).await??,
            read_timeout: Some(read_timeout),
            write_timeout: Some(write_timeout),
        })
    }

    pub fn alpn(&self) -> Option<&str> {
        self.stream.alpn()
    }
}

#[cfg(cls_async)]
impl TimeoutRW<TlsStream<ProxyStream<TcpStream>>> for AsyncTlsStream {
    fn stream(&mut self) -> &mut TlsStream<ProxyStream<TcpStream>> {
        &mut self.stream
    }

    fn read_timeout(&self) -> Option<Duration> {
        self.read_timeout
    }

    fn write_timeout(&self) -> Option<Duration> {
        self.write_timeout
    }
}
