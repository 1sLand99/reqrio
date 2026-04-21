use std::collections::HashMap;
use crate::stream::config::Config;
use crate::*;
#[cfg(feature = "aync")]
pub use aync::TlsStream;
#[cfg(feature = "aync")]
use aync::{TcpStreamA, TimeoutRW, TlsStreamA};
pub use config::{ClientConfig, ServerConfig};
pub use proxy::Proxy;
pub use proxy::ProxyStream;
use std::io::Write;
use std::path::PathBuf;
pub use sync_stream::SyncStream;
pub use ws::{WebSocket, WebSocketBuilder};

mod sync_stream;

mod proxy;
mod ws;
mod config;
#[cfg(feature = "aync")]
mod aync;

pub struct ConnParam<'a> {
    pub scheme: &'a Scheme,
    pub addr: &'a Addr,
    pub proxy: &'a Proxy,
    pub timeout: &'a Timeout,
    pub fingerprint: &'a mut Fingerprint,
    pub alpn: &'a ALPN,
    pub verify: bool,
    pub cert: &'a mut Vec<Certificate>,
    pub key: &'a RsaKey,
    pub ca_cert: &'a Vec<Certificate>,
    pub key_log: &'a Option<PathBuf>,
}

pub enum Stream {
    NonConnection,
    //同步
    SyncHttp(ProxyStream<std::net::TcpStream>),
    SyncHttps(SyncStream<ProxyStream<std::net::TcpStream>>),
    //异步
    #[cfg(feature = "aync")]
    AsyncHttp(TcpStreamA),
    #[cfg(feature = "aync")]
    AsyncHttps(TlsStreamA),
}

#[cfg(feature = "aync")]
impl Stream {
    pub async fn async_conn(&mut self, param: ConnParam<'_>) -> HlsResult<ALPN> {
        let _ = self.async_shutdown().await;
        let st = Time::now_mills().unwrap();
        let stream = tokio::time::timeout(param.timeout.connect(), ProxyStream::async_connect(param.proxy, param.addr)).await??;
        println!("TCP TIME: {}", Time::now_mills().unwrap() - st);
        match param.scheme {
            Scheme::Http | Scheme::Ws => {
                *self = Stream::AsyncHttp(TcpStreamA::from_proxy_stream(stream, param.timeout));
                Ok(ALPN::Http11)
            }
            Scheme::Https | Scheme::Wss => {
                let st = Time::now_mills().unwrap();
                let tls_stream = TlsStreamA::connect_timeout(param, stream).await?;
                println!("TLS TIME: {}", Time::now_mills().unwrap() - st);
                let alpn = tls_stream.alpn().cloned().unwrap_or(ALPN::Http11);
                *self = Stream::AsyncHttps(tls_stream);
                Ok(alpn)
            }
            _ => Err("stream not supported".into())
        }
    }


    pub async fn async_write(&mut self, buf: &[u8]) -> HlsResult<()> {
        match self {
            Stream::AsyncHttp(s) => s.write_all(buf).await,
            Stream::AsyncHttps(s) => s.write_all(buf).await,
            _ => Err("Unsupported async write".into()),
        }
    }

    pub async fn async_read(&mut self, buffer: &mut Buffer) -> HlsResult<()> {
        match self {
            Stream::AsyncHttp(s) => s.read(buffer).await,
            Stream::AsyncHttps(s) => Ok(s.read(buffer).await?),
            _ => Err("Unsupported async read".into()),
        }
    }

    pub async fn async_shutdown(&mut self) -> HlsResult<()> {
        match self {
            Stream::AsyncHttp(s) => Ok(s.shutdown().await?),
            Stream::AsyncHttps(s) => Ok(s.shutdown().await?),
            _ => Err("Unsupported async read".into()),
        }
    }
}

impl Stream {
    pub fn sync_conn(&mut self, param: ConnParam) -> HlsResult<ALPN> {
        let _ = self.sync_shutdown();
        let stream = ProxyStream::sync_connect(param.proxy, param.addr, param.timeout)?;
        match param.scheme {
            Scheme::Http | Scheme::Ws => {
                *self = Stream::SyncHttp(stream);
                Ok(ALPN::Http11)
            }
            Scheme::Https | Scheme::Wss => {
                let t = crate::Time::now_mills().unwrap();
                let tls_stream = SyncStream::connect(ClientConfig::from(param), stream)?;
                println!("TLS TIME: {}", crate::Time::now_mills().unwrap() - t);
                let alpn = tls_stream.alpn().map(|x| ALPN::from_slice(x.as_bytes())).unwrap_or(ALPN::Http11);
                *self = Stream::SyncHttps(tls_stream);
                Ok(alpn)
            }
            _ => Err("stream not supported".into())
        }
    }

    pub fn sync_write(&mut self, buf: &[u8]) -> HlsResult<()> {
        match self {
            Stream::SyncHttp(s) => {
                s.write_all(buf)?;
                Ok(())
            }
            Stream::SyncHttps(s) => {
                s.write_all(buf)?;
                Ok(())
            }
            _ => Err("Unsupported sync write".into()),
        }
    }

    pub fn sync_read(&mut self, buffer: &mut Buffer) -> HlsResult<()> {
        match self {
            Stream::SyncHttp(s) => buffer.sync_read(s),
            Stream::SyncHttps(s) => buffer.sync_read(s),
            _ => Err("Unsupported async read".into()),
        }
    }

    pub fn sync_shutdown(&mut self) -> HlsResult<()> {
        match self {
            Stream::SyncHttp(s) => Ok(s.shutdown()?),
            Stream::SyncHttps(s) => Ok(s.shutdown()?),
            _ => Err("Unsupported async read".into()),
        }
    }
}


pub trait TlsStreamHandle {
    fn conn_buf(&mut self) -> (&mut Connection, &mut Buffer, &mut Buffer);

    fn handle_client_hello(&mut self, config: &mut ClientConfig) -> HlsResult<()> {
        let (conn, _, buffer) = self.conn_buf();
        let session_id = rand::random::<[u8; 32]>();
        let mut record = RecordLayer::from_bytes(&config.fingerprint.client_hello, None)?;
        let client_hello = record.messages[0].client_mut().ok_or(HlsError::NullPointer)?;
        client_hello.set_random(conn.client_random());
        client_hello.set_server_name(config.sni);
        client_hello.set_session_id(&session_id);
        match config.alpn {
            ALPN::Http20 => client_hello.add_h2_alpn(),
            _ => client_hello.remove_h2_alpn()
        }
        let mut secrets = HashMap::new();
        match client_hello.key_share_mut() {
            //fingerprint not supported tls1.3
            None => client_hello.remove_tls13(),
            Some(key_share) => {
                key_share.key_entries().iter().for_each(|key| {
                    if let Ok(secret) = SecretKey::new(key.name_curve()) {
                        secrets.insert(*key.name_curve(), secret);
                    }
                });
                for key_entry in key_share.key_entries_mut() {
                    if let Some(secret) = secrets.get(key_entry.name_curve()) {
                        key_entry.set_exchange_key(secret.pub_key()?)
                    }
                }
            }
        }
        let len = record.write_to(buffer, 1)?;
        buffer.set_len(len);
        conn.set_secret_keys(secrets);
        conn.update_session(&buffer.filled()[5..])?;
        Ok(())
    }

    fn handle_server_hello((conn, buffer): (&mut Connection, &mut Buffer), server_hello: ServerHello) -> Result<(), RlsError> {
        let hello_retry = conn.set_by_server_hello(&server_hello)?;
        if hello_retry {
            let mut reader = Reader::from_slice(conn.session_bytes());
            reader.read_u8()?;
            let mut client = ClientHello::from_bytes(&mut reader)?;
            let mut secrets = HashMap::new();
            for entry in server_hello.key_share_extend().ok_or(HandShakeError::RetryNoKeyShare)?.key_entries() {
                let secret = SecretKey::new(entry.name_curve())?;
                secrets.insert(*entry.name_curve(), secret);
            }
            let mut key_share = KeyShare::default();
            for (name_curve, secret) in secrets.iter_mut() {
                key_share.add_entry(*name_curve, secret.pub_key()?);
            }
            client.set_key_share(key_share);
            let record = RecordLayer {
                context_type: RecordType::HandShake,
                len: 0,
                version: Version::TLS_1_2,
                messages: vec![Message::ClientHello(client)],
            };
            let record_len = record.write_to(buffer, 1)?;
            buffer.set_len(record_len);
            conn.hello_retry(&buffer.filled()[5..])?;
            conn.set_secret_keys(secrets);
        }
        Ok(())
    }

    fn handle_server_hello_done(&mut self, config: &mut Config) -> HlsResult<()> {
        let config = config.client_mut().ok_or("missing config")?;
        let (conn, _, buffer) = self.conn_buf();
        let offset = buffer.len();
        if conn.mtls() {
            //client certificate
            let mut certificate = Certificates::default();
            if let Some(cert) = config.client_cert.get_mut(0) {
                certificate.add_certificate(cert.as_der()?.as_slice());
            }
            let mut record = RecordLayer::handshake();
            record.messages.push(Message::Certificate(certificate));
            let len = record.write_to(buffer, 1)?;
            buffer.set_len(offset + len);
            conn.update_session(&buffer[offset + 5..offset + len])?;
        }
        let offset = buffer.len();
        //client key exchange
        let mut record = RecordLayer::from_bytes(&config.fingerprint.client_key_exchange, None)?;
        let client_key_exchange = record.messages.get_mut(0).ok_or(HlsError::NullPointer)?;
        let key_size = conn.cipher_suite().key_size();
        let pub_key = conn.pub_share_key()?;
        client_key_exchange.client_key_exchange_mut().unwrap().set_pub_key(pub_key.as_ref());
        let len = record.write_to(buffer, key_size)?;
        buffer.set_len(offset + len);
        conn.update_session(&buffer[offset + 5..offset + len])?;
        conn.make_cipher(false)?;
        //certificate verify
        if conn.mtls() && !config.client_cert.is_empty() {
            let offset = buffer.len();
            let len = conn.handle_mtls_client(buffer, config.cert_key)?;
            buffer.set_len(offset + len);
            conn.update_session(&buffer[offset + 5..offset + len])?;
        }
        buffer.write_slice(&config.fingerprint.change_cipher_spec)?;


        let record_len = conn.make_finish_message(buffer.unfilled_mut(), false)?;
        buffer.add_len(record_len);
        Ok(())
    }

    fn handle_by_alert(&mut self, handshake: bool, record_len: usize) -> Result<Alert, RlsError> {
        let (conn, buffer, _) = self.conn_buf();
        match handshake {
            true => {
                let mut out = vec![0; 40];
                let len = conn.read_message(&buffer[..record_len], &mut out)?;
                Ok(Alert::from_bytes(&out[..len])?)
            }
            false => Ok(Alert::from_bytes(&buffer[5..7])?)
        }
    }

    fn handle_message(message: Message<'_>, conn: &mut Connection) -> Result<bool, RlsError> {
        match message {
            Message::Finished(finish) => {
                conn.verify_finish(finish.as_ref(), true)?;

                return Ok(true);
            }
            Message::EncryptedExtension(ee) => conn.set_by_encrypted_extension(&ee),
            _ => {}
        }
        Ok(false)
    }

    fn handle_by_application(&mut self, record_len: usize) -> Result<bool, RlsError> {
        let (conn, r_buf, w_buf) = self.conn_buf();
        w_buf.reset();
        let len = conn.read_message(&r_buf.filled()[..record_len], w_buf.unfilled_mut())?;
        let record_type = RecordType::from_byte(w_buf[len - 1]).ok_or("Invalid record type")?;
        let mut index = 0;
        while index < len - 1 {
            let len = u32::from_be_bytes([0, w_buf[index + 1], w_buf[index + 2], w_buf[index + 3]]) as usize + 4;
            let message = Message::from_bytes(&w_buf[index..index + len], &record_type, None, Version::TLS_1_3)?;
            let finish = Self::handle_message(message, conn)?;
            if finish {
                w_buf.reset();
                w_buf.write_slice(&[20, 3, 3, 0, 1, 1])?;
                let len = conn.make_finish_message(w_buf.unfilled_mut(), false)?;
                w_buf.add_len(len);
                conn.make_cipher(false)?;
                return Ok(true);
            }

            conn.update_session(&w_buf[index..index + len])?;
            index += len;
        }
        Ok(false)
    }
}