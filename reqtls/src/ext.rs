use std::collections::HashMap;
#[cfg(feature = "log")]
use log::{debug, trace, warn};
use crate::*;
use crate::config::{ClientConfig, Config};
use crate::error::RlsResult;

pub struct StreamParam<'a> {
    pub handshake_finish: &'a mut bool,
    pub encrypted_channel: &'a mut bool,
    pub write_buffer: &'a mut Buffer,
    pub conn: &'a mut Connection,
}

pub trait StreamHandle {
    const CHANGE_CIPHER_SPEC: [u8; 6] = [20, 3, 3, 0, 1, 1];

    fn stream_param(&mut self) -> (&mut Buffer, StreamParam<'_>);

    fn handle_client_hello(&mut self, config: &mut ClientConfig) -> RlsResult<()> {
        let (_, param) = self.stream_param();
        let mut client_hello = config.fingerprint.build_client_hello(config.alpn)?;
        client_hello.set_random(param.conn.client_random());
        client_hello.set_server_name(config.sni);
        client_hello.set_session_id(param.conn.session().session_id());
        let ticket = param.conn.session().ticket();
        client_hello.set_session_ticket(ticket);
        let padding = client_hello.padding();
        if padding > ticket.len() {
            client_hello.set_padding(padding - ticket.len());
        } else {
            client_hello.remove_padding();
        };
        let mut secrets = HashMap::new();
        match client_hello.key_share_mut() {
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
        let mut record = RecordLayer::handshake();
        record.messages = vec![client_hello.into()];
        record.version = Version::TLS_1_0;

        let len = record.write_to(param.write_buffer, 1)?;
        param.write_buffer.set_len(len);
        param.conn.set_secret_keys(secrets);
        param.conn.update_session(&param.write_buffer.filled()[5..])?;
        Ok(())
    }

    /// 处理ServerHello，当为HelloRetry时准备新的ClientHello
    /// * `param` - 流参数
    /// * `server_hello` - 已解析的结构
    /// * 返回是否为hello_retry
    fn handle_server_hello(param: &mut StreamParam<'_>, server_hello: ServerHello) -> Result<bool, RlsError> {
        let hello_retry = param.conn.set_by_server_hello(&server_hello)?;
        if hello_retry {
            #[cfg(feature = "log")]
            debug!("[ParsingServerHello] hello_retry=true; retry_share={:?}",server_hello.key_share_extend().map(|x|x.key_entry().name_curve()));
            let mut reader = Reader::from_slice(param.conn.session_bytes());
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
                content_type: RecordType::HandShake,
                len: 0,
                version: Version::TLS_1_2,
                messages: vec![Message::new_parsed(MessageParsed::ClientHello(client))],
            };
            let record_len = record.write_to(param.write_buffer, 1)?;
            param.write_buffer.set_len(record_len);
            param.conn.hello_retry(&param.write_buffer.filled()[5..])?;
            param.conn.set_secret_keys(secrets);
            return Ok(true);
        }
        Ok(false)
    }

    fn handle_server_hello_done(param: &mut StreamParam<'_>, config: &mut Config) -> Result<(), RlsError> {
        let config = config.client_mut().ok_or("missing config")?;
        let offset = param.write_buffer.len();
        if param.conn.mtls() {
            //client certificate
            let mut certificate = Certificates::default();
            if let Some(cert) = config.client_cert.get_mut(0) {
                certificate.add_certificate(cert.as_der()?.as_slice());
            }
            let mut record = RecordLayer::handshake();
            record.messages.push(certificate.into());
            let len = record.write_to(param.write_buffer, 1)?;
            param.write_buffer.set_len(offset + len);
            param.conn.update_session(&param.write_buffer.filled()[offset + 5..offset + len])?;
        }
        let offset = param.write_buffer.len();
        //client key exchange
        let mut client_key_exchange = ClientKeyExchange::default();
        let key_size = param.conn.cipher_suite().key_size();
        let pub_key = param.conn.pub_share_key()?;
        client_key_exchange.set_pub_key(pub_key.as_ref());
        let mut record = RecordLayer::handshake();
        record.messages.push(client_key_exchange.into());
        let len = record.write_to(param.write_buffer, key_size)?;
        param.write_buffer.set_len(offset + len);
        param.conn.update_session(&param.write_buffer.filled()[offset + 5..offset + len])?;
        param.conn.make_cipher(false, false)?;
        //certificate verify
        if param.conn.mtls() && !config.client_cert.is_empty() {
            let offset = param.write_buffer.len();
            let len = param.conn.handle_mtls_client(param.write_buffer, config.cert_key)?;
            param.write_buffer.set_len(offset + len);
            param.conn.update_session(&param.write_buffer.filled()[offset + 5..offset + len])?;
        }
        param.write_buffer.write_slice(&Self::CHANGE_CIPHER_SPEC)?;
        let record_len = param.conn.make_finish_message(param.write_buffer.unfilled_mut(), false)?;
        param.write_buffer.add_len(record_len);
        Ok(())
    }

    fn handle_by_alert(&mut self) -> Result<Alert, RlsError> {
        let (read_buffer, param) = self.stream_param();
        match param.encrypted_channel {
            true => {
                let len = param.conn.read_message(read_buffer.filled(), param.write_buffer.unfilled_mut())?;
                Ok(Alert::from_bytes(&param.write_buffer.unfilled_mut()[..len])?)
            }
            false => Ok(Alert::from_bytes(&read_buffer.filled()[5..7])?)
        }
    }

    fn handle_handshake(param: &mut StreamParam<'_>, mut config: Option<&mut Config<'_>>, messages: Vec<Message<'_>>) -> Result<(), RlsError> {
        for message in messages {
            #[cfg(feature = "log")]
            trace!("[HandleHandshake] message: {:?}]", message);
            match message.parsed {
                MessageParsed::ServerHello(server_hello) => {
                    param.conn.update_session(message.encoded.as_ref())?;
                    let hello_retry = Self::handle_server_hello(param, server_hello)?;
                    if hello_retry { return Ok(()); }
                }
                MessageParsed::Certificate(v) => {
                    param.conn.update_session(message.encoded.as_ref())?;
                    let config = config.as_mut().ok_or("conn param can't be null")?;
                    let config = config.client_mut().ok_or("missing config")?;
                    param.conn.set_by_certificate(v, config.ca_certs, config.sni)?;
                }
                MessageParsed::CertificateStatus(_) => param.conn.update_session(message.encoded.as_ref())?,
                MessageParsed::ServerKeyExchange(v) => {
                    param.conn.update_session(message.encoded.as_ref())?;
                    param.conn.set_by_server_exchange_key(v)?
                }
                MessageParsed::ServerHelloDone(_) => {
                    param.conn.update_session(message.encoded)?;
                    let config = config.as_mut().ok_or("conn param can't be null")?;
                    Self::handle_server_hello_done(param, config)?;
                    *param.handshake_finish = true;
                    return Ok(());
                }
                MessageParsed::ClientHello(mut v) => {
                    param.conn.update_session(&param.write_buffer.filled()[5..])?;
                    let config = config.as_mut().ok_or("config can't be null")?;
                    let random = rand::random::<[u8; 32]>();
                    let server = config.server_mut().ok_or("missing config")?;
                    let mut record = param.conn.gen_server_hello(&mut v, server.server_cert, server.cert_key, &random)?;
                    let session_id = rand::random::<[u8; 32]>();
                    record.messages[0].parsed.server_mut().ok_or(RlsError::NullPtr)?.set_session_id(&session_id);

                    let len = record.write_to(param.write_buffer, 1)?;
                    param.write_buffer.add_len(len);
                    return Ok(());
                }
                MessageParsed::ClientKeyExchange(v) => {
                    param.conn.update_session(message.encoded.as_ref())?;
                    param.conn.set_by_client_exchange_key(v);
                    param.conn.make_cipher(true, false)?;
                }
                // MessageParsed::Payload(_) => {
                //     let record_len = record.len as usize + 5;
                //     let mut out = vec![0; record_len];
                //     let len = self.conn.read_message(&self.read_buffer[..record_len], &mut out)?;
                //     self.conn.verify_finish(&out[..len], false)?;
                //
                //     let mut ticket = SessionTicket::default();
                //     let tbs = rand::random::<[u8; 276]>();
                //     ticket.tls_ticket_mut().set_value(&tbs);
                //     self.write_buffer.write_slice(&[22, 3, 3])?;
                //     self.write_buffer.write_u16(ticket.len() as u16)?;
                //     ticket.write_to(&mut self.write_buffer)?;
                //     self.conn.update_session(&self.write_buffer.filled()[5..])?;
                //     self.write_buffer.write_slice(&[20, 3, 3, 0, 1, 1])?;
                //     let record_len = self.conn.make_finish_message(self.write_buffer.unfilled_mut(), true)?;
                //     self.write_buffer.add_len(record_len);
                //     self.stream.write_all(self.write_buffer.filled())?;
                //     self.write_buffer.reset();
                //     return Ok(true);
                // }
                MessageParsed::CertificateRequest(v) => {
                    param.conn.update_session(message.encoded.as_ref())?;
                    let config = config.as_mut().ok_or("config can't be null")?;
                    let config = config.client_mut().ok_or("missing config")?;
                    param.conn.set_by_cert_req(v, config.client_cert.first_mut())?;
                }
                MessageParsed::NewSessionTicket(ticket) => {
                    param.conn.update_session(message.encoded.as_ref())?;
                    param.conn.set_by_session_ticket(ticket)
                }
                MessageParsed::Finished(_) => {
                    param.conn.verify_finish(message.encoded.as_ref(), true)?;
                    param.write_buffer.write_slice(&Self::CHANGE_CIPHER_SPEC)?;
                    let len = param.conn.make_finish_message(param.write_buffer.unfilled_mut(), false)?;
                    param.write_buffer.add_len(len);
                    param.conn.make_cipher(false, false)?;
                    *param.handshake_finish = true;
                }
                MessageParsed::EncryptedExtension(ee) => {
                    param.conn.set_by_encrypted_extension(&ee);
                    param.conn.update_session(message.encoded.as_ref())?;
                }
                MessageParsed::CompressedCertificate(cc) => {
                    let config = config.as_mut().ok_or("config can't be null")?;
                    let config = config.client_mut().ok_or("missing config")?;
                    param.conn.set_by_compressed_certificate(cc, config.ca_certs, config.sni)?;
                    param.conn.update_session(message.encoded.as_ref())?;
                }
                MessageParsed::CertificateVerify(verify) => {
                    param.conn.verify_cert(verify, true)?;
                    param.conn.update_session(message.encoded.as_ref())?;
                }
                _ => {
                    #[cfg(feature = "log")]
                    warn!("unhandled message: {:?}", message);
                }
            }
        }
        Ok(())
    }


    fn handle_record(&mut self, record_len: usize, config: Option<&mut Config<'_>>, app_buf: &mut [u8]) -> Result<usize, RlsError> {
        let (read_buffer, mut param) = self.stream_param();
        let record = RecordLayer::from_bytes(read_buffer.filled(), None, *param.encrypted_channel)?;
        #[cfg(feature = "log")]
        trace!("[HandleRecord] {:?}", record);
        match record.content_type {
            RecordType::CipherSpec => {
                *param.encrypted_channel = true;
                if param.conn.secret_key().is_none() && param.conn.version() == &Version::TLS_1_2 {
                    param.conn.make_cipher(false, true)?;
                }
            }
            RecordType::Alert => return Err(RlsError::Alert(self.handle_by_alert()?)),
            RecordType::HandShake => match *param.encrypted_channel {
                true => {
                    let out = param.write_buffer.unfilled_mut();
                    let len = param.conn.read_message(&read_buffer.filled()[..record_len], out)?;
                    param.conn.verify_finish(&out[..len], true)?;
                    if param.conn.secret_key().is_none() && param.conn.version() == &Version::TLS_1_2 {
                        #[cfg(feature = "log")]
                        debug!("[HandleRecord] Recover TLS_1.2");
                        param.write_buffer.write_slice(&Self::CHANGE_CIPHER_SPEC)?;
                        let len = param.conn.make_finish_message(param.write_buffer.unfilled_mut(), false)?;
                        param.write_buffer.add_len(len);
                        *param.handshake_finish = true;
                    }
                }
                false => Self::handle_handshake(&mut param, config, record.messages)?
            }
            RecordType::ApplicationData => return self.handle_by_application(record_len, config, app_buf),
        }
        read_buffer.used_empty(record_len);
        Ok(0)
    }


    fn handle_by_application(&mut self, record_len: usize, config: Option<&mut Config>, app_buf: &mut [u8]) -> Result<usize, RlsError> {
        let (read_buffer, mut param) = self.stream_param();
        let len = match *param.conn.version() {
            Version::TLS_1_3 => {
                let len = param.conn.read_message(&read_buffer.filled()[..record_len], app_buf)?;
                let record_type = RecordType::from_byte(app_buf[len - 1])?;
                match record_type {
                    RecordType::Alert => return Err(RlsError::Alert(Alert::from_bytes(&app_buf[..len - 1])?)),
                    RecordType::HandShake => {
                        let mut messages = vec![];
                        let mut msg_readers = Reader::from_slice(&app_buf[..len - 1]);
                        while msg_readers.unread_len() > 0 {
                            messages.push(Message::from_reader(&mut msg_readers, &record_type, Some(param.conn.cipher_suite()), param.conn.version())?);
                        }
                        Self::handle_handshake(&mut param, config, messages)?;
                        0
                    }
                    RecordType::CipherSpec => {
                        *param.encrypted_channel = true;
                        0
                    }
                    RecordType::ApplicationData => len - 1
                }
            }
            _ => param.conn.read_message(&read_buffer.filled()[..record_len], app_buf)?
        };
        read_buffer.used_empty(record_len);
        Ok(len)
    }
}