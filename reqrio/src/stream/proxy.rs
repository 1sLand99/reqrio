use crate::error::{HlsError, HlsResult};
use crate::*;
use std::fmt::{Display, Formatter};
use std::net::Shutdown;
use std::net::SocketAddr;
#[cfg(feature = "aync")]
use std::pin::Pin;
#[cfg(feature = "aync")]
use std::task::{Context, Poll};
#[cfg(feature = "aync")]
use tokio::io::ReadBuf;

#[derive(Clone, Debug)]
pub enum Proxy {
    Null,
    HttpPlain(Url),
    Socks5(Url),
}

impl Proxy {
    pub fn new_http_plain(host: impl ToString, port: u16) -> Proxy {
        let mut url = Url::default();
        url.set_addr(Addr::new_addr(host, port));
        url.set_scheme(Scheme::Http);
        Proxy::HttpPlain(url)
    }

    pub fn new_socks5(host: impl ToString, port: u16) -> Proxy {
        let mut url = Url::default();
        url.set_addr(Addr::new_addr(host, port));
        url.set_scheme(Scheme::Socks5);
        Proxy::Socks5(url)
    }

    fn write_context<W: WriteExt>(&self, peer_addr: &Addr, writer: &mut W, index: usize) -> HlsResult<bool> {
        match self {
            Proxy::Null => return Ok(true),
            Proxy::HttpPlain(v) => {
                let peer_addr = peer_addr.to_string();
                //line1
                writer.write_slice(b"CONNECT ");
                writer.write_slice(peer_addr.as_bytes());
                writer.write_slice(b" HTTP/1.1\r\n");
                //line2
                writer.write_slice(b"Host: ");
                writer.write_slice(peer_addr.as_bytes());
                writer.write_slice(b"\r\n");
                if !v.username().is_empty() && !v.password().is_empty() {
                    writer.write_slice(b"Proxy-Authorization: Basic ");
                    let auth = base64::b64encode(format!("{}:{}", v.username(), v.password()))?;
                    writer.write_slice(auth.as_bytes());
                    writer.write_slice(b"\r\n");
                }
                //line3
                writer.write_slice(b"Proxy-Connection: Keep-Alive\r\n\r\n");
                return Ok(true);
            }
            Proxy::Socks5(v) => {
                if index == 0 {
                    if v.username().is_empty() || v.password().is_empty() {
                        //认证方法-无认证
                        writer.write_slice(&[5, 1, 0]);
                    } else {
                        //认证方法-账号密码
                        writer.write_slice(&[5, 1, 2]);
                    }
                }
                if index == 1 {
                    if v.username().is_empty() || v.password().is_empty() {
                        //认证方法-无认证
                        // index = 2;
                    } else {
                        //认证方法-账号密码
                        writer.write_u8(1);
                        writer.write_u8(v.username().len() as u8);
                        writer.write_slice(v.username().as_bytes());
                        writer.write_u8(v.password().len() as u8);
                        writer.write_slice(v.password().as_bytes());
                    }
                }
                if index == 2 {
                    writer.write_slice(&[5, 1, 0, 3]);
                    writer.write_u8(peer_addr.host().len() as u8);
                    writer.write_slice(peer_addr.host().as_bytes());
                    writer.write_u16(peer_addr.port());
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Proxy::Null)
    }

    pub fn socket_addr(&self, peer_addr: &Addr) -> HlsResult<SocketAddr> {
        match self {
            Proxy::Null => Ok(peer_addr.socket_addr_v4()?),
            Proxy::HttpPlain(url) => Ok(url.addr().socket_addr_v4()?),
            Proxy::Socks5(url) => Ok(url.addr().socket_addr_v4()?),
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
            Scheme::Http => Ok(Proxy::HttpPlain(url)),
            Scheme::Socks5 => Ok(Proxy::Socks5(url)),
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

pub struct ProxyStream<S> {
    stream: S,
    handle_proxy: bool,
    http_proxy: bool,
    buffer: Buffer,
    resp: Response,
}

impl<S> ProxyStream<S> {
    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }
}

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
        let mut buffer = Buffer::with_capacity(1024);
        for i in 0..4 {
            buffer.reset();
            let finish = proxy.write_context(peer_addr, &mut buffer, i)?;
            if buffer.is_empty() { continue; }
            std::io::Write::write_all(&mut stream, buffer.filled())?;
            if finish { break; }
        }
        buffer.reset();
        Ok(ProxyStream {
            stream,
            handle_proxy: matches!(proxy,Proxy::Null),
            http_proxy: matches!(proxy, Proxy::HttpPlain(_)),
            buffer,
            resp: Response::new(),
        })
    }

    pub fn shutdown(&mut self) -> HlsResult<()> {
        self.stream.shutdown(Shutdown::Both)?;
        Ok(())
    }
}

impl std::io::Read for ProxyStream<std::net::TcpStream> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if !self.handle_proxy {
            self.handle_proxy = true;
            self.buffer.reset();
            if self.http_proxy {
                loop {
                    self.buffer.sync_read(&mut self.stream)?;
                    if self.resp.extend_buffer(&mut self.buffer)? { break; }
                }
                let status = self.resp.header().status().code();
                if status != 200 { return Err(std::io::Error::other(format!("connect http proxy error-{}", status))); }
            } else {
                self.buffer.sync_read(&mut self.stream)?;
                if self.buffer.filled().starts_with(&[5, 2]) {
                    if self.buffer.len() == 2 {
                        self.buffer.sync_read(&mut self.stream)?;
                    }
                    if self.buffer[3] != 0 { return Err(std::io::Error::other("socks5 auth fail")); }
                    self.buffer.used_empty(2);
                }
                self.buffer.used_empty(2);
                if self.buffer.is_empty() {
                    self.buffer.sync_read(&mut self.stream)?;
                }
                self.buffer.used_empty(10);
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

impl std::io::Write for ProxyStream<std::net::TcpStream> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        std::io::Write::write(&mut self.stream, buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::Write::flush(&mut self.stream)
    }
}

#[cfg(feature = "aync")]
impl ProxyStream<tokio::net::TcpStream> {
    pub async fn async_connect(proxy: &Proxy, peer_addr: &Addr) -> HlsResult<ProxyStream<tokio::net::TcpStream>> {
        let addr = proxy.socket_addr(peer_addr)?;
        let mut stream = tokio::net::TcpStream::connect(addr).await?;
        let mut buffer = Buffer::with_capacity(1024);
        for i in 0..4 {
            buffer.reset();
            let finish = proxy.write_context(peer_addr, &mut buffer, i)?;
            if buffer.is_empty() { continue; }
            tokio::io::AsyncWriteExt::write_all(&mut stream, buffer.filled()).await?;
            if finish { break; }
        }
        buffer.reset();
        Ok(ProxyStream {
            stream,
            handle_proxy: matches!(proxy,Proxy::Null),
            http_proxy: matches!(proxy, Proxy::HttpPlain(_)),
            buffer,
            resp: Response::new(),
        })
    }
}

#[cfg(feature = "aync")]
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
                            let finished = stream.resp.extend_buffer(&mut stream.buffer)?;
                            if finished { break; }
                        }
                    }
                }
                let status = stream.resp.header().status();
                if status.code() != 200 { return Poll::Ready(Err(std::io::Error::other(format!("connect http proxy fail-{}", status.code())))); }
            } else {
                loop {
                    let mut pb = ReadBuf::new(stream.buffer.unfilled_mut());
                    match Pin::new(&mut stream.stream).poll_read(cx, &mut pb) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) => {
                            let rl = pb.filled().len();
                            if rl == 0 { return Poll::Ready(Err(std::io::Error::other(HlsError::PeerClosedConnection))); }
                            stream.buffer.set_len(stream.buffer.len() + rl);
                            if stream.buffer.len() < 2 { continue; }
                            if stream.buffer[1] == 2 {
                                if stream.buffer.len() < 4 { continue; }
                                if stream.buffer[3] == 0 {
                                    if stream.buffer.len() >= 14 {
                                        stream.buffer.used_empty(14);
                                        break;
                                    }
                                } else { return Poll::Ready(Err(std::io::Error::other("socks5 auth fail"))); }
                            } else if stream.buffer.len() >= 12 {
                                stream.buffer.used_empty(12);
                                break;
                            }
                        }
                    }
                }
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

#[cfg(feature = "aync")]
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
