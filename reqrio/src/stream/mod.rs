use crate::stream::config::Config;
use crate::stream::kind::StreamKind;
use crate::*;
pub use sync_stream::SyncStream;
#[cfg(feature = "aync")]
pub use async_stream::TlsStream;
pub use config::{ClientConfig, ServerConfig};
pub use proxy::Proxy;
pub use proxy::ProxyStream;
pub use ws::{WebSocket, WebSocketBuilder};

#[cfg(feature = "aync")]
mod async_stream;

mod sync_stream;

#[cfg(feature = "aync")]
mod astream;
mod proxy;
mod kind;
mod ws;
mod config;


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
}

pub struct Stream {
    alpn: ALPN,
    kind: StreamKind,
}

impl Stream {
    pub fn unconnection() -> Self {
        Stream {
            alpn: ALPN::Http11,
            kind: StreamKind::NonConnection,
        }
    }
    pub fn alpn(&self) -> &ALPN {
        &self.alpn
    }
}

#[cfg(feature = "aync")]
impl Stream {
    pub async fn async_connect(&mut self, param: ConnParam<'_>) -> HlsResult<()> {
        let alpn = self.kind.async_conn(param).await?;
        self.alpn = alpn;
        Ok(())
    }
    pub async fn async_read(&mut self, buffer: &mut Buffer) -> HlsResult<()> {
        self.kind.async_read(buffer).await
    }

    pub async fn async_write(&mut self, data: &[u8]) -> HlsResult<()> {
        self.kind.async_write(data).await
    }

    pub async fn async_shutdown(&mut self) -> HlsResult<()> {
        self.kind.async_shutdown().await
    }
}

impl Stream {
    pub fn sync_connect(&mut self, param: ConnParam) -> HlsResult<()> {
        let _ = self.sync_shutdown();
        let alpn = self.kind.sync_conn(param)?;
        self.alpn = alpn;
        Ok(())
    }
    pub fn sync_read(&mut self, buffer: &mut Buffer) -> HlsResult<()> {
        self.kind.sync_read(buffer)
    }

    pub fn sync_write(&mut self, data: &[u8]) -> HlsResult<()> {
        self.kind.sync_write(data)
    }

    pub fn sync_shutdown(&mut self) -> HlsResult<()> {
        self.kind.sync_shutdown()
    }
}


pub trait TlsStreamHandle {
    fn conn_wbuf(&mut self) -> (&mut Connection, &mut Buffer);

    fn conn_rbuf(&mut self) -> (&mut Connection, &mut Buffer);

    fn handle_client_hello(config: &mut ClientConfig, buffer: &mut Buffer) -> HlsResult<Connection> {
        let client_random = rand::random::<[u8; 32]>().to_vec();
        let session_id = rand::random::<[u8; 32]>();
        let mut client_hello = RecordLayer::from_bytes(&mut config.fingerprint.client_hello, false, None)?;
        client_hello.messages[0].client_mut().ok_or(HlsError::NullPointer)?.set_random(&client_random);
        client_hello.messages[0].client_mut().ok_or(HlsError::NullPointer)?.set_server_name(config.sni);
        client_hello.messages[0].client_mut().ok_or(HlsError::NullPointer)?.set_session_id(&session_id);
        // client_hello.messages[0].client_mut().ok_or(HlsError::NullPointer)?.set_cipher_suites(vec![
        //     CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        //     CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        //     CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        //     //ecdsa
        //     CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        //     CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        //     CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        // ]);
        match config.alpn {
            ALPN::Http20 => client_hello.messages[0].client_mut().ok_or(HlsError::NullPointer)?.add_h2_alpn(),
            _ => client_hello.messages[0].client_mut().ok_or(HlsError::NullPointer)?.remove_h2_alpn()
        }
        client_hello.messages[0].client_mut().ok_or(HlsError::NullPointer)?.remove_tls13();
        let len = client_hello.write_to(buffer, 1)?;
        buffer.set_len(len);

        let mut conn = Connection::default().with_client_random(client_random).with_verify(config.verify);
        conn.update_session(&buffer.filled()[5..])?;
        Ok(conn)
    }

    fn handle_by_server_hello_done(&mut self, mut config: Option<&mut Config>) -> HlsResult<()> {
        let config = config.as_mut().ok_or("config can't be null")?;
        let config = config.client_mut().ok_or("missing config")?;
        let (conn, buffer) = self.conn_wbuf();
        let offset = buffer.len();
        if conn.mtls() {
            //client certificate
            // if config.client_cert.is_empty() { return Err("Server request cert, but not provided".into()); }
            let mut certificate = Certificates::default();
            if let Some(cert) = config.client_cert.get_mut(0) {
                certificate.add_certificate(cert.as_der().as_slice());
            }
            let mut record = RecordLayer::handshake();
            record.messages.push(Message::Certificate(certificate));
            let len = record.write_to(buffer, 1)?;
            buffer.set_len(offset + len);
            conn.update_session(&buffer[offset + 5..offset + len])?;
        }
        let offset = buffer.len();
        //client key exchange
        let mut record = RecordLayer::from_bytes(&mut config.fingerprint.client_key_exchange, false, None)?;
        let client_key_exchange = record.messages.get_mut(0).ok_or(HlsError::NullPointer)?;
        let key_size = conn.cipher_suite().key_size();
        let pub_key = conn.pub_share_key()?;
        client_key_exchange.client_key_exchange_mut().unwrap().set_pub_key(pub_key.as_slice());
        let len = record.write_to(buffer, key_size)?;
        buffer.set_len(offset + len);
        conn.update_session(&buffer[offset + 5..offset + len])?;
        conn.make_cipher(false)?;
        //certificate verify
        if conn.mtls() && config.client_cert.len() > 0 {
            let offset = buffer.len();
            let len = conn.handle_mtls_client(buffer, config.cert_key)?;
            buffer.set_len(offset + len);
            conn.update_session(&buffer[offset + 5..offset + len])?;
        }
        buffer.write_slice(&config.fingerprint.change_cipher_spec);


        let record_len = conn.make_finish_message(buffer.unfilled_mut(), false)?;
        buffer.add_len(record_len);
        Ok(())
    }

    fn handle_by_alert(&mut self, handshake: bool, record_len: usize) -> Result<Alert, RlsError> {
        let (conn, buffer) = self.conn_rbuf();
        match handshake {
            true => {
                let mut out = vec![0; 40];
                let len = conn.read_message(&buffer[..record_len], &mut out)?;
                Ok(Alert::from_bytes(&out[..len])?)
            }
            false => Ok(Alert::from_bytes(&buffer[5..7])?)
        }
    }
}