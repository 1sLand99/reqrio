use crate::error::HlsResult;
use crate::Buffer;
use crate::*;
use std::mem;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};

pub(super) enum Handshake<S> {
    Handshaking(Box<TlsStream<S>>),
    Finished,
}


pub struct Connecting<'a, S> {
    pub(super) handshake: Handshake<S>,
    pub(super) config: Config<'a>,
    pub(super) sent_client_hello: bool,
}


impl<'a, S: AsyncRead + AsyncWrite + Unpin> Future for Connecting<'a, S> {
    type Output = HlsResult<TlsStream<S>>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let connector = self.get_mut();
        let stream = match connector.handshake {
            Handshake::Handshaking(ref mut stream) => stream,
            Handshake::Finished => return Poll::Ready(Err(RlsError::HandShake(HandShakeError::PollWhileFinish).into())),
        };
        if !connector.sent_client_hello {
            if stream.write_buffer.is_empty() {
                stream.handle_client_hello(connector.config.client_mut().ok_or("missing config")?)?;
            }
            connector.sent_client_hello = true;
        }
        let mut buffer = Buffer::with_capacity(16438);
        let stream = loop {
            if !stream.write_buffer.is_empty() {
                match stream.write_buffer(cx)? {
                    Poll::Ready(_) => {}
                    Poll::Pending => return Poll::Pending,
                }
            }
            if stream.handshake_finished && stream.write_buffer.is_empty() { break mem::replace(&mut connector.handshake, Handshake::Finished); }
            let record_len = match stream.read_next_record(cx)? {
                Poll::Ready(len) => len,
                Poll::Pending => return Poll::Pending,
            };
            stream.handle_record(record_len, Some(&mut connector.config), buffer.unfilled())?;
        };
        match stream {
            Handshake::Handshaking(mut stream) => {
                if stream.conn.version() == &Version::TLS_1_3 {
                    stream.conn.make_cipher(false)?;
                }
                stream.read_buffer.move_to(stream.read_buffer.offset(), 0)?;
                stream.write_buffer.reset();
                Poll::Ready(Ok(*stream))
            }
            Handshake::Finished => Poll::Ready(Err(RlsError::HandShake(HandShakeError::PollWhileFinish).into())),
        }
    }
}