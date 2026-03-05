use std::io;
use crate::stream::config::{ClientConfig, Config, ServerConfig};
use crate::*;
use std::io::Error;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use crate::stream::TlsStreamHandle;

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
    async fn new(stream: S, conn: Connection, mut config: Config<'_>, buffer: Buffer) -> HlsResult<TlsStream<S>> {
        let mut stream = TlsStream {
            stream,
            conn,
            handshake_finished: false,
            read_buffer: Buffer::with_capacity(16437),
            write_buffer: buffer,
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
    pub async fn connect(mut stream: S, mut config: ClientConfig<'_>) -> HlsResult<TlsStream<S>> {
        let mut write_buffer = Buffer::with_capacity(0xFFFF);
        let conn = Self::handle_client_hello(&mut config, &mut write_buffer)?;
        stream.write_all(write_buffer.filled()).await?;
        write_buffer.reset();
        TlsStream::new(stream, conn, Config::Client(config), write_buffer).await
    }

    pub async fn accept(stream: S, config: ServerConfig<'_>) -> HlsResult<TlsStream<S>> {
        TlsStream::new(stream, Connection::default(), Config::Server(config), Buffer::with_capacity(16437)).await
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

    async fn handle_message(&mut self, mut config: Option<&mut Config<'_>>) -> HlsResult<bool> {
        let record = RecordLayer::from_bytes(self.read_buffer.filled_mut(), self.handshake_finished, Some(self.conn.cipher_suite()))?;
        match record.context_type {
            RecordType::CipherSpec => self.handshake_finished = true,
            RecordType::Alert => {
                let record_len = record.len as usize + 5;
                return Err(self.handle_by_alert(self.handshake_finished, record_len)?.into());
            }
            RecordType::HandShake => {
                for message in record.messages {
                    match message {
                        Message::ServerHello(v) => self.conn.set_by_server_hello(&v)?,
                        Message::Certificate(v) => {
                            let config = config.as_mut().ok_or("config can't be null")?;
                            self.conn.set_by_certificate(v, config.client_mut().ok_or("missing config")?.sni)?;
                        }
                        Message::ServerKeyExchange(v) => self.conn.set_by_server_exchange_key(v)?,
                        Message::ServerHelloDone(_) => {
                            self.handle_by_server_hello_done(config)?;
                            self.stream.write_all(self.write_buffer.filled()).await?;
                            self.write_buffer.reset();
                            return Ok(true);
                        }
                        Message::ClientHello(v) => {
                            let len = record.len as usize + 5;
                            let config = config.as_mut().ok_or("config can't be null")?;
                            let random = rand::random::<[u8; 32]>();
                            let server = config.server_mut().ok_or("missing config")?;
                            let mut record = self.conn.gen_server_hello(v, server.server_cert, server.cert_key, &random)?;
                            let session_id = rand::random::<[u8; 32]>();
                            record.messages[0].server_mut().ok_or(HlsError::NullPointer)?.set_session_id(&session_id);

                            record.write_to(&mut self.write_buffer, 1)?;
                            self.conn.update_session(&self.write_buffer.filled()[5..])?;
                            self.stream.write_all(self.write_buffer.filled()).await?;
                            self.client_hello.extend_from_slice(self.read_buffer[..len].as_ref());
                            self.write_buffer.reset();
                            break;
                        }
                        Message::ClientKeyExchange(v) => {
                            self.conn.set_by_client_exchange_key(v);
                            self.conn.make_cipher(true)?;
                        }
                        Message::Payload(_) => {
                            // let mut record = RecordLayer::from_bytes(self.read_buffer.filled_mut(), self.handshake_finished, None)?;
                            let record_len = record.len as usize + 5;
                            let mut out = vec![0; record_len];
                            let len = self.conn.read_message(&self.read_buffer[..record_len], &mut out)?;
                            self.conn.verify_finish(&out[..len], false)?;

                            let mut ticket = SessionTicket::default();
                            let tbs = rand::random::<[u8; 276]>();
                            ticket.tls_ticket_mut().set_value(&tbs);
                            self.write_buffer.write_slice(&[22, 3, 3]);
                            self.write_buffer.write_u16(ticket.len() as u16);
                            ticket.write_to(&mut self.write_buffer);
                            self.conn.update_session(&self.write_buffer.filled()[5..])?;
                            self.write_buffer.write_slice(&[20, 3, 3, 0, 1, 1]);
                            let record_len = self.conn.make_finish_message(self.write_buffer.unfilled_mut(), true)?;
                            self.write_buffer.add_len(record_len);
                            self.stream.write_all(self.write_buffer.filled()).await?;
                            self.write_buffer.reset();
                            return Ok(true);
                        }
                        Message::CertificateRequest(v) => {
                            let config = config.as_mut().ok_or("config can't be null")?;
                            let config = config.client_mut().ok_or("missing config")?;
                            self.conn.set_by_cert_req(v, config.client_cert.first_mut())?;
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

impl<S> TlsStreamHandle for TlsStream<S> {
    fn conn_wbuf(&mut self) -> (&mut Connection, &mut Buffer) {
        (&mut self.conn, &mut self.write_buffer)
    }

    fn conn_rbuf(&mut self) -> (&mut Connection, &mut Buffer) {
        (&mut self.conn, &mut self.read_buffer)
    }
}

impl<S> TlsStream<S> {
    fn read_message(&mut self, buf: &mut ReadBuf<'_>) -> io::Result<usize> {
        let record = RecordLayer::from_bytes(self.read_buffer.filled_mut(), self.handshake_finished, None)?;
        let record_len = record.len as usize + 5;
        match record.context_type {
            RecordType::CipherSpec => {
                self.handshake_finished = true;
                self.read_buffer.move_to(record_len..self.read_buffer.len(), 0);
            }
            RecordType::Alert => return Err(self.handle_by_alert(self.handshake_finished, record_len)?.into()),
            RecordType::HandShake => {
                if self.handshake_finished {
                    let len = self.conn.read_message(&self.read_buffer[..record_len], buf.initialized_mut())?;
                    self.conn.verify_finish(&buf.initialized()[..len], true)?;
                } else {
                    self.conn.update_session(&self.read_buffer[5..record_len])?;
                }
                self.read_buffer.move_to(record_len..self.read_buffer.len(), 0);
            }
            RecordType::ApplicationData => {
                let len = self.conn.read_message(&self.read_buffer[..record_len], buf.initialized_mut())?;
                buf.set_filled(len);
                self.read_buffer.move_to(record_len..self.read_buffer.len(), 0);
                return Ok(len);
            }
        }
        Ok(0)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for TlsStream<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
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
            if stream.read_buffer.unfilled_mut().is_empty() { return Poll::Ready(Err(Error::other("buffer size  too small"))); }
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

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let stream = self.get_mut();
        if stream.write_buffer.is_empty() {
            let len = stream.conn.make_message(RecordType::Alert, &mut stream.write_buffer[..], &Alert::close_notify().to_bytes())?;
            stream.write_buffer.set_len(len);
        }
        match stream.shutdown_wrote {
            true => Pin::new(&mut stream.stream).poll_shutdown(cx),
            false => match Pin::new(&mut stream.stream).poll_write(cx, stream.write_buffer.filled()) {
                Poll::Ready(Ok(_)) => {
                    stream.shutdown_wrote = true;
                    Pin::new(&mut stream.stream).poll_shutdown(cx)
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        }
    }
}
