use crate::error::{HlsError, HlsResult};
use crate::*;
use std::io::Error;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};


pub struct TlsStream<S> {
    conn: Connection,
    stream: S,
    handshake_finished: bool,
    read_buffer: Buffer,
    write_buffer: Buffer,
    shutdown_wrote: bool,
    wrote_len: usize,
    pending: Vec<usize>,
    client_hello: Vec<u8>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> TlsStream<S> {
    async fn new(stream: S, conn: Connection, mut config: TlsConfig<'_>) -> HlsResult<TlsStream<S>> {
        let mut stream = TlsStream {
            stream,
            conn,
            handshake_finished: false,
            read_buffer: Buffer::with_capacity(16413),
            write_buffer: Buffer::with_capacity(16413),
            shutdown_wrote: false,
            wrote_len: 0,
            pending: vec![],
            client_hello: vec![],
        };
        loop {
            let record_len = stream.read_packet().await?;
            let hello_done = stream.handle_message(Some(&mut config)).await?;
            stream.read_buffer.move_to(record_len..stream.read_buffer.len(), 0);
            if hello_done { break; }
        }
        Ok(stream)
    }
    pub async fn connect(mut stream: S, config: TlsConfig<'_>) -> HlsResult<TlsStream<S>> {
        let client_random = rand::random::<[u8; 32]>().to_vec();
        let session_id = rand::random::<[u8; 32]>();

        let mut record = RecordLayer::from_bytes(config.fingerprint.client_hello_mut(), false, None)?;
        let message = record.messages.get_mut(0).ok_or(RlsError::ClientHelloNone)?;
        message.client_mut().ok_or(HlsError::NullPointer)?.set_random(&client_random);
        message.client_mut().ok_or(HlsError::NullPointer)?.set_server_name(config.sni);
        message.client_mut().ok_or(HlsError::NullPointer)?.set_session_id(&session_id);
        match config.alpn {
            ALPN::Http20 => message.client_mut().ok_or(HlsError::NullPointer)?.add_h2_alpn(),
            _ => message.client_mut().ok_or(HlsError::NullPointer)?.remove_h2_alpn()
        }
        message.client_mut().ok_or(HlsError::NullPointer)?.remove_tls13();
        let bs = record.handshake_bytes(1);
        let mut conn = Connection::default().with_client_random(client_random).with_verify(config.verify);
        conn.update_session(&bs[5..])?;
        stream.write_all(&bs).await?;
        TlsStream::new(stream, conn, config).await
    }

    pub async fn accept(stream: S, config: TlsConfig<'_>) -> HlsResult<TlsStream<S>> {
        TlsStream::new(stream, Connection::default(), config).await
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
        if !self.handshake_finished && self.read_buffer[0] == 22 { self.conn.update_session(&self.read_buffer[5..record_len])?; }
        Ok(record_len)
    }

    async fn handle_message(&mut self, mut config: Option<&mut TlsConfig<'_>>) -> HlsResult<bool> {
        let mut record = RecordLayer::from_bytes(self.read_buffer.filled_mut(), self.handshake_finished, Some(self.conn.cipher_suite()))?;
        match record.context_type {
            RecordType::CipherSpec => self.handshake_finished = true,
            RecordType::Alert => {
                let pdr = if self.handshake_finished { self.conn.read_message(&mut record)? } else { 5..record.len as usize + 5 };
                let alert = Alert::from_bytes(&self.read_buffer[pdr])?;
                return Err(alert.as_err().into());
            }
            RecordType::HandShake => {
                for message in record.messages {
                    match message {
                        Message::ServerHello(v) => self.conn.set_by_server_hello(v)?,
                        Message::Certificate(v) => {
                            let config = config.as_mut().ok_or("config can't be null")?;
                            self.conn.set_by_certificate(v, config.sni)?;
                        }
                        Message::ServerKeyExchange(v) => self.conn.set_by_server_exchange_key(v)?,
                        Message::ServerHelloDone(_) => {
                            let config = config.as_mut().ok_or("config can't be null")?;
                            let mut record = RecordLayer::from_bytes(config.fingerprint.client_key_exchange_mut(), false, None)?;
                            let client_key_exchange = record.messages.get_mut(0).ok_or(HlsError::NullPointer)?;
                            let key_size = self.conn.cipher_suite().key_size();
                            let pub_key = self.conn.pub_share_key()?;
                            client_key_exchange.client_key_exchange_mut().unwrap().set_pub_key(pub_key.as_slice());
                            let bs = record.handshake_bytes(key_size);
                            self.conn.update_session(&bs[5..])?;
                            self.write_buffer.push_slice(&bs);
                            self.write_buffer.push_slice(config.fingerprint.change_cipher_spec());

                            self.conn.make_cipher(false)?;
                            let record_len = self.conn.make_finish_message(self.write_buffer.unfilled_mut(), false)?;

                            self.write_buffer.set_len(self.write_buffer.len() + record_len);
                            self.stream.write_all(self.write_buffer.filled()).await?;
                            self.write_buffer.reset();
                            return Ok(true);
                        }
                        Message::ClientHello(v) => {
                            let config = config.as_mut().ok_or("config can't be null")?;
                            let bytes = self.conn.gen_server_hello(v, config.certificate, config.private_key)?;
                            self.stream.write_all(&bytes).await?;
                            let record_len = record.len as usize + 5;
                            self.client_hello.extend_from_slice(self.read_buffer[..record_len].as_ref());
                            break;
                        }
                        Message::ClientKeyExchange(v) => {
                            self.conn.set_by_client_exchange_key(v);
                            self.conn.make_cipher(true)?;
                        }
                        Message::Payload(_) => {
                            let mut record = RecordLayer::from_bytes(self.read_buffer.filled_mut(), self.handshake_finished, None)?;
                            let pdr = self.conn.read_message(&mut record)?;
                            self.conn.verify_finish(&self.read_buffer[pdr], false)?;

                            let mut ticket = SessionTicket::new();
                            ticket.tls_ticket_mut().set_value(rand::random::<[u8; 276]>().to_vec());
                            let ticket_bytes = ticket.as_bytes();
                            self.write_buffer.push_slice(&[22, 3, 3]);
                            self.write_buffer.push_u16(ticket_bytes.len() as u16);
                            self.write_buffer.push_slice(&ticket_bytes);
                            self.write_buffer.push_slice(&[20, 3, 3, 0, 1, 1]);
                            self.conn.update_session(&ticket_bytes)?;
                            let record_len = self.conn.make_finish_message(self.write_buffer.unfilled_mut(), true)?;
                            self.write_buffer.add_len(record_len);
                            self.stream.write_all(self.write_buffer.filled()).await?;
                            self.write_buffer.reset();
                            return Ok(true);
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

    pub fn client_hello(&self) -> &[u8] { &self.client_hello }
}


impl<S> TlsStream<S> {
    fn read_message(&mut self, buf: &mut ReadBuf<'_>) -> std::io::Result<usize> {
        let mut record = RecordLayer::from_bytes(self.read_buffer.filled_mut(), self.handshake_finished, None)?;
        let record_len = record.len as usize + 5;
        match record.context_type {
            RecordType::CipherSpec => {
                self.handshake_finished = true;
                self.read_buffer.move_to(record_len..self.read_buffer.len(), 0);
            }
            RecordType::Alert => {
                let pdr = if self.handshake_finished { self.conn.read_message(&mut record)? } else { 5..record.len as usize + 5 };
                let alert = Alert::from_bytes(&self.read_buffer[pdr])?;
                return Err(Error::other(alert.desc().to_string()));
            }
            RecordType::HandShake => {
                if self.handshake_finished {
                    let pdr = self.conn.read_message(&mut record)?;
                    self.conn.verify_finish(&self.read_buffer[pdr], true)?;
                } else {
                    self.conn.update_session(&self.read_buffer[5..record_len])?;
                }
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
                Poll::Ready(Ok(len)) => {
                    if stream.write_buffer.used_empty(len) {
                        stream.pending.remove(0);
                        stream.write_buffer.reset();
                    }
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
            false => match self.as_mut().poll_write(cx, &Alert::close_notify().to_bytes()) {
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

unsafe impl<S> Send for TlsStream<S> {}

unsafe impl<S> Sync for TlsStream<S> {}