use crate::error::{HlsError, HlsResult};
use crate::*;
use std::io;
use std::io::{Read, Write};

pub struct SyncStream<S> {
    conn: Connection,
    stream: S,
    handshake_finished: bool,
    read_buffer: Buffer,
    write_buffer: Buffer,
}

impl<S: Read + Write> SyncStream<S> {
    pub fn connect(mut config: TlsConfig, mut stream: S) -> HlsResult<SyncStream<S>> {
        let client_random = rand::random::<[u8; 32]>().to_vec();
        let session_id = rand::random::<[u8; 32]>();
        let mut client_hello = RecordLayer::from_bytes(config.fingerprint.client_hello_mut(), false, None)?;
        client_hello.messages[0].client_mut().ok_or(HlsError::NullPointer)?.set_random(&client_random);
        client_hello.messages[0].client_mut().ok_or(HlsError::NullPointer)?.set_server_name(config.sni);
        client_hello.messages[0].client_mut().ok_or(HlsError::NullPointer)?.set_session_id(&session_id);
        match config.alpn {
            ALPN::Http20 => client_hello.messages[0].client_mut().ok_or(HlsError::NullPointer)?.add_h2_alpn(),
            _ => client_hello.messages[0].client_mut().ok_or(HlsError::NullPointer)?.remove_h2_alpn()
        }
        client_hello.messages[0].client_mut().ok_or(HlsError::NullPointer)?.remove_tls13();
        let bs = client_hello.handshake_bytes(1);
        let mut conn = Connection::default().with_client_random(client_random).with_verify(config.verify);
        conn.update_session(&bs[5..])?;
        stream.write_all(&bs)?;
        let mut stream = SyncStream {
            stream,
            conn,
            handshake_finished: false,
            read_buffer: Buffer::with_capacity(0xFFFF),
            write_buffer: Buffer::with_capacity(0xFFFF),
        };
        loop {
            let record_len = stream.read_next_packet()?;
            let len = stream.read_buffer.len();
            let hello_done = stream.handle_message(Some(&mut config))?;
            stream.read_buffer.move_to(record_len..len, 0);
            if hello_done { break; }
        }
        Ok(stream)
    }

    fn handle_message(&mut self, mut param: Option<&mut TlsConfig>) -> HlsResult<bool> {
        let record = RecordLayer::from_bytes(self.read_buffer.filled_mut(), self.handshake_finished, Some(self.conn.cipher_suite()))?;
        // println!("{:#?}", record);
        for message in record.messages {
            match record.context_type {
                RecordType::CipherSpec => self.handshake_finished = true,
                RecordType::Alert => {}
                RecordType::HandShake => {
                    match message {
                        Message::ServerHello(v) => self.conn.set_by_server_hello(v)?,
                        Message::Certificate(v) => {
                            let param = param.as_mut().ok_or("conn param can't be null")?;
                            self.conn.set_by_certificate(v, param.sni)?;
                        }
                        Message::ServerKeyExchange(v) => {
                            // println!("{:#?}", v);
                            self.conn.set_by_server_exchange_key(v)?
                        }
                        Message::ServerHelloDone(_) => {
                            let param = param.as_mut().ok_or("conn param can't be null")?;
                            let key_size=self.conn.cipher_suite().key_size();
                            let pub_key = self.conn.pub_share_key()?;
                            let mut client_key_exchange = RecordLayer::from_bytes(param.fingerprint.client_key_exchange_mut(), false, None)?;
                            client_key_exchange.messages[0].client_key_exchange_mut().unwrap().set_pub_key(pub_key.as_slice());
                            let bs = client_key_exchange.handshake_bytes(key_size);
                            self.conn.update_session(&bs[5..])?;
                            self.stream.write_all(&bs)?;

                            self.stream.write_all(param.fingerprint.change_cipher_spec())?;
                            self.conn.make_cipher(false)?;

                            self.write_buffer.reset();
                            let record_len = self.conn.make_finish_message(&mut self.write_buffer[..], false)?;
                            self.stream.write_all(&self.write_buffer[..record_len])?;
                            return Ok(true);
                        }
                        _ => {}
                    }
                }
                RecordType::ApplicationData => {}
            }
        }

        Ok(false)
    }

    pub fn shutdown(&mut self) -> HlsResult<()> {
        self.write_buffer.reset();
        let record_len = self.conn.make_message(RecordType::Alert, &mut self.write_buffer[..], &[1, 0])?;
        self.stream.write_all(&self.write_buffer[..record_len])?;
        Ok(())
    }

    pub fn alpn(&self) -> Option<&str> {
        Some(self.conn.alpn()?.value())
    }
}

impl<S: Read> SyncStream<S> {
    fn read_size(&mut self, size: usize) -> HlsResult<()> {
        let start = self.read_buffer.len();
        while self.read_buffer.len() - start < size {
            self.read_buffer.sync_read(&mut self.stream)?;
        }
        Ok(())
    }

    fn check_and_read(&mut self) -> HlsResult<usize> {
        let len = u16::from_be_bytes([self.read_buffer[3], self.read_buffer[4]]) as usize;
        if self.read_buffer.len() >= len + 5 {
            Ok(len + 5)
        } else {
            self.read_size(len + 5 - self.read_buffer.len())?;
            Ok(len + 5)
        }
    }

    fn read_zero(&mut self) -> HlsResult<usize> {
        self.read_buffer.sync_read(&mut self.stream)?;
        self.check_and_read()
    }

    fn read_next_packet(&mut self) -> HlsResult<usize> {
        let record_len = if self.read_buffer.len() >= 5 {
            self.check_and_read()?
        } else {
            self.read_zero()?
        };
        if !self.handshake_finished { self.conn.update_session(&self.read_buffer.filled()[5..record_len])?; }
        Ok(record_len)
    }
}

impl<S: Read + Write> Read for SyncStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let record_len = self.read_next_packet()?;
            let mut record = RecordLayer::from_bytes(&mut self.read_buffer[0..record_len], self.handshake_finished, None)?;
            match record.context_type {
                RecordType::CipherSpec | RecordType::HandShake => {
                    if self.handshake_finished { self.conn.read_message(&mut record)?; } else { let _ = self.handle_message(None)?; }
                    self.read_buffer.move_to(record_len..self.read_buffer.len(), 0);
                    continue;
                }
                RecordType::Alert => {
                    let pdr = if self.handshake_finished { self.conn.read_message(&mut record)? } else { 5..record_len };
                    if self.read_buffer[pdr.clone()] == [1, 0] { return Err(HlsError::PeerClosedConnection.into()); }
                    self.read_buffer.move_to(record_len..self.read_buffer.len(), 0);
                }
                RecordType::ApplicationData => {
                    let pdr = self.conn.read_message(&mut record)?;
                    buf[..pdr.len()].copy_from_slice(&self.read_buffer[pdr.clone()]);
                    self.read_buffer.move_to(record_len..self.read_buffer.len(), 0);
                    return Ok(pdr.len());
                }
            }
        };
    }
}


impl<S: Write> Write for SyncStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut sent = 0;
        for chunk in buf.chunks(16384) {
            self.write_buffer.reset();
            loop {
                let record_len = self.conn.make_message(RecordType::ApplicationData, &mut self.write_buffer[..], chunk)?;
                self.write_buffer.set_len(record_len);
                let len = self.stream.write(self.write_buffer.filled())?;
                if self.write_buffer.used_empty(len) { break; }
            }
            sent += chunk.len();
        }
        Ok(sent)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}