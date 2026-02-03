use crate::error::{HlsError, HlsResult};
use crate::stream::ConnParam;
use crate::*;
use std::io::Error;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};


pub struct TlsConnector<'a> {
    sni: &'a str,
    fingerprint: &'a mut Fingerprint,
    alpn: &'a ALPN,
}

impl<'a> TlsConnector<'a> {
    pub async fn connect<S: AsyncRead + AsyncWrite + Unpin>(self, stream: S) -> HlsResult<TlsStream<S>> {
        TlsStream::connect(self, stream).await
    }
}

impl<'a> From<(&'a str, &'a mut Fingerprint, &'a ALPN)> for TlsConnector<'a> {
    fn from((sni, fingerprint, alpn): (&'a str, &'a mut Fingerprint, &'a ALPN)) -> Self {
        TlsConnector {
            sni,
            fingerprint,
            alpn,
        }
    }
}

impl<'a> From<ConnParam<'a>> for TlsConnector<'a> {
    fn from(value: ConnParam<'a>) -> Self {
        TlsConnector {
            sni: value.url.addr().host(),
            fingerprint: value.fingerprint,
            alpn: value.alpn,
        }
    }
}

pub struct TlsStream<S> {
    conn: Connection,
    stream: S,
    handshake_finished: bool,
    read_buffer: Buffer,
    write_buffer: Buffer,
    shutdown_wrote: bool,
    wrote_len: usize,
    pending: Vec<usize>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> TlsStream<S> {
    pub async fn connect(mut connector: TlsConnector<'_>, mut stream: S) -> HlsResult<TlsStream<S>> {
        let client_random = rand::random::<[u8; 32]>();
        let mut conn = Connection::default().with_client_random(client_random.to_vec());
        let mut record = RecordLayer::from_bytes(connector.fingerprint.client_hello_mut(), false)?;
        let message = record.messages.get_mut(0).ok_or(RlsError::ClientHelloNone)?;
        message.client_mut().ok_or(HlsError::NullPointer)?.set_random(client_random);
        message.client_mut().ok_or(HlsError::NullPointer)?.set_server_name(connector.sni);
        message.client_mut().ok_or(HlsError::NullPointer)?.set_session_id(rand::random());
        match connector.alpn {
            ALPN::Http20 => message.client_mut().ok_or(HlsError::NullPointer)?.add_h2_alpn(),
            _ => message.client_mut().ok_or(HlsError::NullPointer)?.remove_h2_alpn()
        }
        message.client_mut().ok_or(HlsError::NullPointer)?.remove_tls13();
        let bs = record.handshake_bytes();
        conn.update_session(&bs[5..])?;
        stream.write_all(&bs).await?;
        let mut stream = TlsStream {
            stream,
            conn,
            handshake_finished: false,
            read_buffer: Buffer::with_capacity(16413),
            write_buffer: Buffer::with_capacity(16413),
            shutdown_wrote: false,
            wrote_len: 0,
            pending: vec![],
        };
        loop {
            let record_len = stream.read_packet().await?;
            let hello_done = stream.handle_message(Some(&mut connector)).await?;
            stream.read_buffer.move_to(record_len..stream.read_buffer.len(), 0);
            if hello_done { break; }
        }
        Ok(stream)
    }

    pub async fn accept(stream: S) -> HlsResult<TlsStream<S>> {
        let mut stream = TlsStream {
            stream,
            conn: Connection::default(),
            handshake_finished: false,
            read_buffer: Buffer::with_capacity(16413),
            write_buffer: Buffer::with_capacity(16413),
            shutdown_wrote: false,
            wrote_len: 0,
            pending: vec![],
        };
        loop {
            let record_len = stream.read_packet().await?;
            stream.handle_message(None).await?;
            stream.read_buffer.move_to(record_len..stream.read_buffer.len(), 0);
            break;
        }
        Ok(stream)
    }

    pub async fn read_packet(&mut self) -> HlsResult<usize> {
        let record_len = match self.read_buffer.is_empty() {
            true => {
                self.read_buffer.async_read(&mut self.stream).await?;
                u16::from_be_bytes([self.read_buffer[3], self.read_buffer[4]]) as usize
            }
            false => u16::from_be_bytes([self.read_buffer[3], self.read_buffer[4]]) as usize,
        } + 5;
        while self.read_buffer.len() < record_len {
            self.read_buffer.async_read(&mut self.stream).await?;
        }
        if !self.handshake_finished { self.conn.update_session(&self.read_buffer[5..record_len])?; }
        Ok(record_len)
    }

    async fn handle_message(&mut self, connector: Option<&mut TlsConnector<'_>>) -> HlsResult<bool> {
        let record = RecordLayer::from_bytes(self.read_buffer.filled_mut(), self.handshake_finished)?;
        println!("{:#?}", record);
        match record.context_type {
            RecordType::CipherSpec => self.handshake_finished = true,
            RecordType::Alert => {}
            RecordType::HandShake => {
                for message in record.messages {
                    match message {
                        Message::ServerHello(v) => {
                            // println!("{:#?}-{}", v.cipher_suite, connector.sni);
                            self.conn.set_by_server_hello(v)?;
                        }
                        Message::ServerKeyExchange(v) => {
                            // println!("{:#?}", v);
                            self.conn.set_by_exchange_key(v.hellman_param().pub_key().clone(), *v.hellman_param().named_curve())
                        }
                        Message::ServerHelloDone(_) => {
                            let connector = connector.ok_or("connector can't be null")?;
                            let mut keypair = PriKey::new(self.conn.named_curve())?;
                            let client_pub_key = keypair.pub_key();
                            let mut record = RecordLayer::from_bytes(connector.fingerprint.client_key_exchange_mut(), false)?;
                            let client_key_exchange = record.messages.get_mut(0).ok_or(HlsError::NullPointer)?;
                            client_key_exchange.client_key_exchange_mut().unwrap().set_pub_key(client_pub_key);
                            let bs = record.handshake_bytes();
                            self.conn.update_session(&bs[5..])?;
                            self.stream.write_all(&bs).await?;

                            self.stream.write_all(connector.fingerprint.change_cipher_spec()).await?;
                            let share_secret = keypair.diffie_hellman(self.conn.server_pub_key().as_ref())?;
                            let handshake_hash = self.conn.session_hash()?;
                            self.conn.make_cipher(&share_secret, handshake_hash.clone())?;

                            let record_len = self.conn.make_finish_message(&handshake_hash, &mut self.write_buffer[..])?;
                            self.stream.write_all(&self.write_buffer[..record_len]).await?;
                            self.write_buffer.reset();
                            return Ok(true);
                        }
                        Message::ClientHello(mut v) => {
                            self.conn.set_client_random(v.take_random());
                            let server_hello = ServerHello::from_client_hello(v)?;
                            let server_hello_bytes = server_hello.as_bytes();
                            self.conn.set_by_server_hello(server_hello)?;







                            let mut record = RecordLayer::new();
                            record.version = Version::TLS_1_2;
                            record.context_type = RecordType::HandShake;
                            record.len = server_hello_bytes.len() as u16;
                            let mut bytes = record.head_bytes();
                            bytes.extend(record.len.to_be_bytes());
                            bytes.extend(server_hello_bytes);
                            let record = RecordLayer::from_bytes(&mut bytes, false).unwrap();
                            println!("{:#?}", record);
                        }
                        _ => {}
                    }
                }
            }
            RecordType::ApplicationData => {}
        }
        Ok(false)
    }

    pub fn alpn(&self) -> Option<&str> {
        Some(self.conn.alpn()?.value())
    }
}


impl<S> TlsStream<S> {
    fn read_message(&mut self, buf: &mut ReadBuf<'_>) -> std::io::Result<usize> {
        let mut record = RecordLayer::from_bytes(self.read_buffer.filled_mut(), self.handshake_finished)?;
        let record_len = record.len as usize + 5;
        match record.context_type {
            RecordType::CipherSpec => {
                self.handshake_finished = true;
                self.read_buffer.move_to(record_len..self.read_buffer.len(), 0);
            }
            RecordType::Alert => {
                let pdr = if self.handshake_finished { self.conn.read_message(&mut record)? } else { 5..record.len as usize + 5 };
                return Err(Error::other(format!("TlsAlert: [{:?}]", &self.read_buffer[pdr])));
            }
            RecordType::HandShake => {
                if self.handshake_finished { self.conn.read_message(&mut record)?; }
                self.read_buffer.move_to(record_len..self.read_buffer.len(), 0);
            }
            RecordType::ApplicationData => {
                let pdr = self.conn.read_message(&mut record)?;
                buf.put_slice(&self.read_buffer[pdr]);
                self.read_buffer.move_to(record_len..self.read_buffer.len(), 0);
                return Ok(record_len);
            }
        }
        Ok(0)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for TlsStream<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        if self.shutdown_wrote { return Poll::Ready(Ok(())); }
        let stream = self.get_mut();
        loop {
            let record_len = if stream.read_buffer.is_empty() { 0 } else { u16::from_be_bytes([stream.read_buffer[3], stream.read_buffer[4]]) as usize + 5 };
            if record_len != 0 && stream.read_buffer.len() >= record_len {
                match stream.read_message(buf) {
                    Ok(len) => if len > 0 { return Poll::Ready(Ok(())); } else { continue; }
                    Err(e) => return Poll::Ready(Err(e)),
                }
            }
            let mut rd = ReadBuf::new(stream.read_buffer.unfilled_mut());
            match Pin::new(&mut stream.stream).poll_read(cx, &mut rd) {
                Poll::Ready(Ok(_)) => {
                    let fl = rd.filled().len();
                    if fl == 0 { return Poll::Ready(Ok(())); }
                    let nl = stream.read_buffer.len() + fl;
                    stream.read_buffer.set_len(nl);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
        }
    }
}


impl<S: AsyncWrite + Unpin> AsyncWrite for TlsStream<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, Error>> {
        let stream = self.get_mut();
        let chucks = buf.chunks(16384).collect::<Vec<_>>();
        if stream.pending.is_empty() {
            stream.wrote_len = 0;
            stream.pending = (0..chucks.len()).collect();
        }
        loop {
            if stream.pending.is_empty() { break; }
            if stream.write_buffer.is_empty() {
                let record_len = stream.conn.make_message(RecordType::ApplicationData, &mut stream.write_buffer[..], chucks[stream.pending[0]])?;
                stream.write_buffer.set_len(record_len);
                stream.wrote_len += chucks[stream.pending[0]].len();
            }
            match Pin::new(&mut stream.stream).poll_write(cx, stream.write_buffer.filled()) {
                Poll::Ready(Ok(_)) => {
                    stream.pending.remove(0);
                    stream.write_buffer.reset();
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        if stream.wrote_len > buf.len() {
            println!("write {} {}", stream.wrote_len, buf.len());
        }
        Poll::Ready(Ok(stream.wrote_len))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        match self.shutdown_wrote {
            true => Pin::new(&mut self.stream).poll_shutdown(cx),
            false => match self.as_mut().poll_write(cx, &[1, 0]) {
                Poll::Ready(Ok(_)) => {
                    self.shutdown_wrote = true;
                    Pin::new(&mut self.stream).poll_shutdown(cx)
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        }
    }
}