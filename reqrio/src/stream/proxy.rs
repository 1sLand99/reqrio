use crate::error::{HlsError, HlsResult};
use crate::url::{Addr, Protocol};
use crate::*;
use std::fmt::{Display, Formatter};
use std::net::SocketAddr;
#[cfg(sync)]
use std::net::Shutdown;
#[cfg(aync)]
use std::pin::Pin;
#[cfg(aync)]
use std::task::{Context, Poll};
#[cfg(aync)]
use tokio::io::ReadBuf;

#[derive(Clone, Debug)]
pub enum Proxy {
    Null,
    HttpPlain(Addr),
    Socks5(Addr),
}

impl Proxy {
    pub fn new_http_plain(host: impl ToString, port: u16) -> Proxy {
        Proxy::HttpPlain(Addr::new_addr(host, port))
    }

    pub fn new_socks5(host: impl ToString, port: u16) -> Proxy {
        Proxy::Socks5(Addr::new_addr(host, port))
    }

    #[cfg(anys)]
    fn proxy_context(&self, peer_addr: &Addr) -> Vec<u8> {
        match self {
            Proxy::Null => vec![],
            Proxy::HttpPlain(_) => [
                format!("CONNECT {} HTTP/1.1", peer_addr),
                format!("Host: {}", peer_addr),
                "Proxy-Connection: Keep-Alive".to_string(),
                "".to_string(),
                "".to_string()
            ].join("\r\n").into_bytes(),
            Proxy::Socks5(_) => {
                let mut data = vec![5, 1, 0, 5, 1, 0, 3];
                data.push(peer_addr.host().len() as u8);
                data.extend_from_slice(peer_addr.host().as_bytes());
                data.extend(peer_addr.port().to_be_bytes());
                data
            }
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Proxy::Null)
}

    pub fn socket_addr(&self, peer_addr: &Addr) -> HlsResult<SocketAddr> {
        match self {
            Proxy::Null => Ok(peer_addr.socket_addr_v4()?),
            Proxy::HttpPlain(addr) => Ok(addr.socket_addr_v4()?),
            Proxy::Socks5(addr) => Ok(addr.socket_addr_v4()?),
        }
    }
}

impl Display for Proxy {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Proxy::Null => f.write_str(""),
            Proxy::HttpPlain(addr) => f.write_str(&format!("http://{}", addr)),
            Proxy::Socks5(addr) => f.write_str(&format!("socks5://{}", addr)),
        }
    }
}

impl TryFrom<&str> for Proxy {
    type Error = HlsError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let url = Url::try_from(value)?;
        match url.protocol() {
            Protocol::Http => Ok(Proxy::HttpPlain(url.addr().clone())),
            Protocol::Socks5 => Ok(Proxy::Socks5(url.addr().clone())),
            _ => Err("unsupported proxy scheme".into())
        }
    }
}

impl TryFrom<String> for Proxy {
    type Error = HlsError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Proxy::try_from(value.as_str())
    }
}

#[cfg(anys)]
pub struct ProxyStream<S> {
    stream: S,
    handle_proxy: bool,
    http_proxy: bool,
    buffer: Buffer,
    #[cfg(aync)]
    resp: Response,
}

#[cfg(anys)]
impl<S> ProxyStream<S> {
    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }
}

#[cfg(sync)]
impl ProxyStream<std::net::TcpStream> {
    fn create_sync(addr: &SocketAddr, timeout: &Timeout) -> HlsResult<std::net::TcpStream> {
        let stream = std::net::TcpStream::connect_timeout(addr, timeout.connect())?;
        stream.set_read_timeout(Some(timeout.read()))?;
        stream.set_write_timeout(Some(timeout.write()))?;
        Ok(stream)
    }
    pub fn sync_connect(proxy: &Proxy, peer_addr: &Addr, timeout: &Timeout) -> HlsResult<ProxyStream<std::net::TcpStream>> {
        let addr = proxy.socket_addr(peer_addr)?;
        let mut stream = ProxyStream::create_sync(&addr, timeout)?;
        let proxy_context = proxy.proxy_context(peer_addr);
        if !proxy_context.is_empty() {
            std::io::Write::write_all(&mut stream, &proxy_context)?;
        }
        Ok(ProxyStream {
            stream,
            handle_proxy: proxy_context.is_empty(),
            http_proxy: matches!(proxy, Proxy::HttpPlain(_)),
            buffer: Buffer::with_capacity(1024),
            #[cfg(aync)]
            resp: Response::new(),
        })
    }

    pub fn shutdown(&mut self) -> HlsResult<()> {
        self.stream.shutdown(Shutdown::Both)?;
        Ok(())
    }
}

#[cfg(sync)]
impl std::io::Read for ProxyStream<std::net::TcpStream> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if !self.handle_proxy {
            self.handle_proxy = true;
            self.buffer.reset();
            if self.http_proxy {
                let mut resp = Response::new();
                loop {
                    self.buffer.reset();
                    self.buffer.sync_read(&mut self.stream)?;
                    if resp.extend(&self.buffer)? { break; }
                }
                let status = resp.header().status().status_num();
                if status != 200 { return Err(std::io::Error::other(format!("connect http proxy error-{}", status))); }
                let pos = self.buffer.filled().windows(HTTP_GAP.len()).position(|window| window == HTTP_GAP);
                let pos = pos.ok_or(std::io::Error::other("connect proxy fail"))? + resp.header().content_length().unwrap_or(0);
                self.buffer.copy_within(pos + 4..self.buffer.len(), 0);
                self.buffer.set_len(self.buffer.len() - pos - 4);
            } else {
                self.buffer.sync_read(&mut self.stream)?;
                if !self.buffer.filled().starts_with(&[5, 0]) {
                    println!("{:?}", self.buffer.filled());
                    return Err(std::io::Error::other("connect socks5 proxy fail".to_string()));
                }
                if self.buffer.len() == 2 {
                    self.buffer.reset();
                    self.buffer.sync_read(&mut self.stream)?;
                }
                self.buffer.copy_within(10..self.buffer.len(), 0);
                self.buffer.set_len(self.buffer.len() - 10);
            }
            if self.buffer.is_empty() {
                self.stream.read(buf)
            } else {
                buf[..self.buffer.len()].copy_from_slice(self.buffer.filled());
                Ok(self.buffer.len())
            }
        } else {
            std::io::Read::read(&mut self.stream, buf)
        }
    }
}

#[cfg(sync)]
impl std::io::Write for ProxyStream<std::net::TcpStream> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        std::io::Write::write(&mut self.stream, buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::Write::flush(&mut self.stream)
    }
}

#[cfg(aync)]
impl ProxyStream<tokio::net::TcpStream> {
    pub async fn async_connect(proxy: &Proxy, peer_addr: &Addr) -> HlsResult<ProxyStream<tokio::net::TcpStream>> {
        let addr = proxy.socket_addr(peer_addr)?;
        let mut stream = tokio::net::TcpStream::connect(addr).await?;
        let proxy_context = proxy.proxy_context(peer_addr);
        if !proxy_context.is_empty() {
            tokio::io::AsyncWriteExt::write_all(&mut stream, &proxy_context).await?;
        }
        Ok(ProxyStream {
            stream,
            handle_proxy: proxy_context.is_empty(),
            http_proxy: matches!(proxy, Proxy::HttpPlain(_)),
            buffer: Buffer::with_capacity(1024),
            resp: Response::new(),
        })
    }
}

#[cfg(aync)]
impl tokio::io::AsyncRead for ProxyStream<tokio::net::TcpStream> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        if !self.handle_proxy {
            let stream = self.get_mut();
            if stream.http_proxy {
                loop {
                    let mut pb = ReadBuf::new(stream.buffer.unfilled_mut());
                    match Pin::new(&mut stream.stream).poll_read(cx, &mut pb) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) => {
                            let rl = pb.filled().len();
                            stream.buffer.set_len(stream.buffer.len() + rl);
                            let finished = stream.resp.extend(&stream.buffer)?;
                            if finished { break; }
                        }
                    }
                }
                let pos = stream.buffer.filled().windows(HTTP_GAP.len()).position(|window| window == HTTP_GAP);
                let pos = pos.ok_or(std::io::Error::other("connect proxy fail"))? + stream.resp.header().content_length().unwrap_or(0);
                stream.buffer.copy_within(pos + 4..stream.buffer.len(), 0);
                stream.buffer.set_len(stream.buffer.len() - pos - 4);
            } else {
                loop {
                    let mut pb = ReadBuf::new(stream.buffer.unfilled_mut());
                    match Pin::new(&mut stream.stream).poll_read(cx, &mut pb) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) => {
                            let rl = pb.filled().len();
                            stream.buffer.set_len(stream.buffer.len() + rl);
                            if stream.buffer.len() >= 12 { break; }
                        }
                    }
                }
                stream.buffer.copy_within(12..stream.buffer.len(), 0);
                stream.buffer.set_len(stream.buffer.len() - 12);
            }
            stream.handle_proxy = true;
            if stream.buffer.is_empty() {
                Pin::new(&mut stream.stream).poll_read(cx, buf)
            } else {
                buf.put_slice(stream.buffer.filled());
                Poll::Ready(Ok(()))
            }
        } else {
            Pin::new(&mut self.stream).poll_read(cx, buf)
        }
    }
}

#[cfg(aync)]
impl tokio::io::AsyncWrite for ProxyStream<tokio::net::TcpStream> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
