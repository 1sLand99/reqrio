use crate::error::HlsResult;
use crate::*;
use std::future::Future;
use std::io::{Read, Write};
use std::mem;
use std::ops::{Deref, DerefMut};
#[cfg(feature = "aync")]
use std::pin::Pin;
#[cfg(feature = "aync")]
use std::task::{Context, Poll};
#[cfg(feature = "aync")]
use tokio::io::{AsyncRead, AsyncWrite};

pub(crate) enum ConnState<S> {
    Connecting(Box<TlsStream<S>>),
    Connected,
}

impl<S> ConnState<S> {
    pub(super) fn take(&mut self) -> TlsStream<S> {
        let state = mem::replace(self, ConnState::Connected);
        match state {
            ConnState::Connecting(stream) => *stream,
            ConnState::Connected => unreachable!(),
        }
    }
}

impl<S> Deref for ConnState<S> {
    type Target = TlsStream<S>;

    fn deref(&self) -> &Self::Target {
        match self {
            ConnState::Connecting(stream) => stream,
            ConnState::Connected => unreachable!()
        }
    }
}

impl<S> DerefMut for ConnState<S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            ConnState::Connecting(stream) => stream,
            ConnState::Connected => unreachable!()
        }
    }
}

pub struct TlsConnecting<'a, S> {
    pub(super) sent_client_hello: bool,
    pub(super) config: Config<'a>,
    pub(crate) state: ConnState<S>,
    pub(super) app_buf: Buffer,
}

impl<'a, S: Read + Write> TlsConnecting<'a, S> {
    pub fn wait(mut self) -> HlsResult<TlsStream<S>> {
        let tls_stream = self.state.deref_mut();
        if !self.sent_client_hello {
            tls_stream.handle_client_hello(self.config.client_mut().ok_or("missing config")?)?;
            self.sent_client_hello = true;
        }
        let mut stream = loop {
            tls_stream.write_buffer().wait()?;
            if tls_stream.handshake_finished && tls_stream.write_buffer.is_empty() { break self.state.take(); }
            let record_len = tls_stream.read_next_record().wait()?;
            tls_stream.handle_record(record_len, Some(&mut self.config), self.app_buf.unfilled())?;
            tls_stream.read_buffer.used_empty(record_len);
        };
        if stream.conn.version() == &Version::TLS_1_3 { stream.conn.make_cipher(false)?; }
        Ok(stream)
    }
}

#[cfg(feature = "aync")]
impl<'a, S: AsyncRead + AsyncWrite + Unpin> Future for TlsConnecting<'a, S> {
    type Output = HlsResult<TlsStream<S>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let connector = self.get_mut();
        if !connector.sent_client_hello {
            if connector.state.write_buffer.is_empty() {
                connector.state.handle_client_hello(connector.config.client_mut().ok_or("missing config")?)?;
            }
            connector.sent_client_hello = true;
        }
        let mut stream = loop {
            if !connector.state.write_buffer.is_empty() {
                let mut writer = connector.state.write_buffer();
                if Pin::new(&mut writer).poll(cx)?.is_pending() {
                    connector.state.timeout.connect_timeout()?;
                    return Poll::Pending;
                }
            }
            if connector.state.handshake_finished && connector.state.write_buffer.is_empty() {
                break connector.state.take();
            }
            let mut reader = connector.state.read_next_record();
            let record_len = match Pin::new(&mut reader).poll(cx)? {
                Poll::Ready(len) => len,
                Poll::Pending => {
                    connector.state.timeout.connect_timeout()?;
                    return Poll::Pending;
                }
            };
            connector.state.handle_record(record_len, Some(&mut connector.config), connector.app_buf.unfilled())?;
            connector.state.read_buffer.used_empty(record_len);
        };
        if stream.conn.version() == &Version::TLS_1_3 { stream.conn.make_cipher(false)?; }
        Poll::Ready(Ok(stream))
    }
}


// pub struct StreamConnect<'a> {
//     pub(crate) stream: &'a mut Stream,
//     pub(crate) shutdown: bool,
//     pub(crate) param: ConnParam<'a>,
// }

// impl<'a> StreamConnect<'a> {
//     pub fn wait(mut self) -> HlsResult<ALPN> {
//         let _ = self.stream.shutdown().wait();
//         let stream = ProxyStream::sync_connect(self.param.proxy, self.param.url.addr(), self.param.timeout, self.param.ech).unwrap();
//         match self.param.url.scheme() {
//             Scheme::Http | Scheme::Ws => {
//                 *self.stream = Stream::SyncHttp(stream);
//                 Ok(ALPN::Http11)
//             }
//             Scheme::Https | Scheme::Wss => {
//                 let tls_stream = TlsStream::connect(ClientConfig::from(&mut self.param), stream).wait().unwrap();
//                 let alpn = tls_stream.alpn().cloned().unwrap_or(ALPN::Http11);
//                 *self.stream = Stream::SyncHttps(tls_stream);
//                 Ok(alpn)
//             }
//             _ => Err("stream not supported".into())
//         }
//     }
// }
// // 
// #[cfg(feature = "aync")]
// impl<'a> Future for StreamConnect<'a> {
//     type Output = HlsResult<ALPN>;
//     fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
//         if !self.shutdown {
//             let mut shutdown = self.stream.shutdown();
//             match Pin::new(&mut shutdown).poll(cx) {
//                 Poll::Ready(_) => self.shutdown = true,
//                 Poll::Pending => return Poll::Pending,
//             }
//         }
// 
// 
//         let reader = self.get_mut();
//         let stream: &mut (dyn AsyncWrite + Unpin) = match reader.stream {
//             Stream::NonConnection => return Poll::Ready(Err("NonConnection".into())),
//             Stream::AsyncHttp(stream) => stream,
//             Stream::AsyncHttps(stream) => stream,
//             _ => unreachable!(),
//         };
//         loop {
//             match Pin::new(&mut *stream).poll_write(cx, &reader.buf[reader.off..])? {
//                 Poll::Ready(len) => {
//                     reader.off += len;
//                     if reader.off >= reader.buf.len() { break; }
//                 }
//                 Poll::Pending => return Poll::Pending,
//             }
//         }
//         Poll::Ready(Ok(()))
//     }
// }