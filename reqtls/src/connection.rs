use super::bytes::Bytes;
use super::record::{RecordLayer, RecordType};
use super::suite::iv::Iv;
use super::suite::CipherSuite;
use super::suite::TlsCipher;
use super::version::Version;
use crate::boring::{certificate, AlgorithmSigner, HashError};
use crate::buffer::{Buf, RecordDecodeBuffer, RecordEncodeBuffer};
use crate::derived::{DerivedKey, Key};
use crate::error::{HandShakeError, RlsResult};
use crate::secret_key::SecretKey;
use crate::*;
use std::mem;
use crate::message::EncryptedExtension;

pub struct Connection {
    read: TlsCipher,
    write: TlsCipher,
    named_curve: NamedCurve,
    exchange_pub_key: Bytes,
    alpn: Option<ALPN>,
    cipher_suite: CipherSuite,
    session_bytes: Vec<u8>,
    derived: DerivedKey,
    certificates: Vec<Certificate>,
    secret_keys: Vec<SecretKey>,
    secret_key: Option<SecretKey>,
    verify: bool,
    root_stores: &'static CertStore,
    mtls_hash: SignatureAlgorithm,
    version: Version,
}
impl Default for Connection {
    fn default() -> Self {
        Connection::new([0; 32], [0; 32])
    }
}

impl Connection {
    pub fn new(client_random: [u8; 32], server_random: [u8; 32]) -> Connection {
        Connection {
            read: TlsCipher::none(),
            write: TlsCipher::none(),
            named_curve: NamedCurve::X25519.into(),
            exchange_pub_key: Bytes::none(),
            alpn: None,
            cipher_suite: CipherSuite::new(0),
            session_bytes: vec![],
            derived: DerivedKey::new(client_random, server_random),
            certificates: vec![],
            verify: false,
            root_stores: &certificate::ROOT_STORES,
            mtls_hash: SignatureAlgorithm::new(0),
            version: Version::TLS_1_2,
            secret_keys: vec![],
            secret_key: None,
        }
    }

    pub fn from_client(random: [u8; 32]) -> Connection {
        Connection::new(random, [0; 32])
    }

    pub fn with_verify(mut self, verify: bool) -> Connection {
        self.verify = verify;
        self
    }

    pub fn disable_verify(mut self) -> Connection {
        self.verify = false;
        self
    }

    pub fn set_by_server_hello(&mut self, server_hello: &ServerHello) -> RlsResult<()> {
        self.alpn = server_hello.alpn();
        self.cipher_suite = server_hello.cipher_suite.as_u16().into();
        self.cipher_suite.init_aead_hasher()?;
        self.cipher_suite.update(&self.session_bytes)?;
        let hasher = self.cipher_suite.hasher().as_ref().ok_or(HashError::HasherNone)?;
        let aead = self.cipher_suite.aead().ok_or(RlsError::AeadNone)?;
        if let Some(version) = server_hello.supported_version() {
            self.version = *version;
        }
        self.derived.init(aead, hasher, &self.version);
        self.derived.set_server_random(server_hello.random.as_ref().try_into()?);
        self.derived.set_ems(server_hello.use_ems());
        if Version::TLS_1_3 == self.version {
            let key_entry = server_hello.share_key().unwrap().key_entry();
            let mut secret_key = self.secret_keys.remove(key_entry.name_curve().secret_index()?);
            let share_secret = secret_key.diffie_hellman(key_entry.exchange_key().as_ref())?;
            self.derived.make_handshake_traffic_secret(share_secret, self.cipher_suite.current_session_hash()?)?;
            let aead = self.cipher_suite.aead().unwrap();
            let hasher = self.cipher_suite.mac_hash().unwrap();
            let key = self.derived.make_tls13_cipher_key()?;
            if let Key::TLS13 {
                send_key,
                send_iv,
                recv_key,
                recv_iv
            } = key.get_side(&self.version, false) {
                self.write.set_key(send_key, &[], aead, hasher)?;
                self.write.set_iv(Iv::new(send_iv, vec![]));
                self.read.set_key(recv_key, &[], aead, hasher)?;
                self.read.set_iv(Iv::new(recv_iv, vec![]));
            }
        }
        Ok(())
    }

    pub fn set_by_encrypted_extension(&mut self, encrypted: &EncryptedExtension) {
        self.alpn = encrypted.alpn().cloned();
    }

    pub fn set_by_certificate(&mut self, certificate: Certificates, ext_cas: &[Certificate], sni: &str) -> RlsResult<()> {
        for certificate in certificate.certificates() {
            self.certificates.push(Certificate::from_der(certificate.as_ref())?);
        }
        if !self.verify { return Ok(()); }
        self.root_stores.verify_cert(&mut self.certificates, ext_cas, sni)
    }

    fn gen_key_sign_data(&self, server_key: &ServerKeyExchange) -> Vec<u8> {
        let mut sign_data = Vec::with_capacity(512);
        sign_data.extend_from_slice(self.derived.client_random());
        sign_data.extend_from_slice(self.derived.server_random());
        sign_data.push(*server_key.hellman_param().curve_type() as u8);
        sign_data.extend(server_key.hellman_param().named_curve().as_u16().to_be_bytes());
        sign_data.push(server_key.hellman_param().pub_key().len() as u8);
        sign_data.extend(server_key.hellman_param().pub_key().as_ref());
        sign_data
    }

    pub fn set_by_cert_req(&mut self, req: CertificateRequest, cert: Option<&mut Certificate>) -> RlsResult<()> {
        if let Some(cert) = cert {
            for hash in req.into_hashes() {
                match (hash.as_u16(), cert.cert_type()?) {
                    (SignatureAlgorithm::RSA_PSS_RSAE_SHA256, CertType::RSA) => self.mtls_hash = hash,
                    (SignatureAlgorithm::RSA_PSS_RSAE_SHA384, CertType::RSA) => self.mtls_hash = hash,
                    (SignatureAlgorithm::RSA_PSS_RSAE_SHA512, CertType::RSA) => self.mtls_hash = hash,
                    (SignatureAlgorithm::ECDSA_SECP256R1_SHA256, CertType::ECDSA) => self.mtls_hash = hash,
                    (SignatureAlgorithm::ECDSA_SECP384R1_SHA384, CertType::ECDSA) => self.mtls_hash = hash,
                    (SignatureAlgorithm::ECDSA_SECP521R1_SHA512, CertType::ECDSA) => self.mtls_hash = hash,
                    (SignatureAlgorithm::RSA_PKCS1_SHA1, CertType::RSA) => self.mtls_hash = hash,
                    (SignatureAlgorithm::RSA_PKCS1_SHA256, CertType::RSA) => self.mtls_hash = hash,
                    (SignatureAlgorithm::RSA_PKCS1_SHA384, CertType::RSA) => self.mtls_hash = hash,
                    (SignatureAlgorithm::RSA_PKCS1_SHA512, CertType::RSA) => self.mtls_hash = hash,
                    _ => continue,
                }
                break;
            }
        } else { self.mtls_hash = SignatureAlgorithm::RSA_PKCS1_SHA1.into() }
        Ok(())
    }

    pub fn set_by_server_exchange_key(&mut self, server_key: ServerKeyExchange) -> RlsResult<()> {
        if self.verify {
            let sign_data = self.gen_key_sign_data(&server_key);
            let signature = AlgorithmSigner::new_verify(self.certificates[0].pub_key()?, server_key.hellman_param().signature_algorithm())?;
            signature.verify(sign_data, server_key.hellman_param().signature().as_ref())?;
        }
        self.exchange_pub_key = Bytes::new(server_key.hellman_param().pub_key().to_vec());
        self.named_curve = *server_key.hellman_param().named_curve();
        let index = self.named_curve.secret_index()?;
        self.secret_key = Some(self.secret_keys.remove(index));
        self.secret_keys.clear();
        self.secret_keys.shrink_to_fit();
        Ok(())
    }

    pub fn set_by_client_exchange_key(&mut self, client_key: ClientKeyExchange) {
        self.exchange_pub_key = Bytes::new(client_key.hellman_param().pub_key().to_vec());
    }

    pub fn pub_share_key(&mut self) -> RlsResult<Buf<'_>> {
        match self.secret_key {
            None => {
                let key = SecretKey::new_pre_master_secret()?;
                let rsa = RsaCipher::new(self.certificates[0].pub_key()?)?;
                let pub_key = Buf::Vec(rsa.encrypt(key.pub_key()?.as_ref())?);
                self.secret_key = Some(key);
                Ok(pub_key)
            }
            Some(ref key) => key.pub_key(),
        }
    }

    pub fn make_cipher(&mut self, server: bool) -> RlsResult<()> {
        if let Version::TLS_1_2 = self.version {
            let secret_key = self.secret_key.as_mut().ok_or("Invalid secret key")?;
            let share_secret = secret_key.diffie_hellman(self.exchange_pub_key.as_ref())?;
            self.derived.make_master(Version::TLS_1_2, share_secret, self.cipher_suite.current_session_hash()?)?;
        }

        let aead = self.cipher_suite.aead().ok_or(RlsError::AeadNone)?;
        let key = self.derived.make_cipher_key(&self.version, server)?;
        let hasher = self.cipher_suite.mac_hash().ok_or(HashError::HasherNone)?;
        match key {
            Key::TLS12 {
                send_mac,
                recv_mac,
                send_key,
                recv_key,
                send_iv,
                recv_iv,
                explicit
            } => {
                self.write.set_key(send_key, send_mac, aead, hasher)?;
                self.write.set_iv(Iv::new(send_iv, explicit.to_vec()));
                self.read.set_key(recv_key, recv_mac, aead, hasher)?;
                self.read.set_iv(Iv::new(recv_iv, vec![]));
            }
            Key::TLS13 {
                send_key,
                send_iv,
                recv_key,
                recv_iv
            } => {
                self.write.set_key(send_key, &[], aead, hasher)?;
                self.write.set_iv(Iv::new(send_iv, vec![]));
                self.read.set_key(recv_key, &[], aead, hasher)?;
                self.read.set_iv(Iv::new(recv_iv, vec![]));
            }
        }
        Ok(())
    }

    pub fn gen_server_hello<'a>(&mut self, client_hello: &'a mut ClientHello<'a>, certificate: &'a mut [Certificate], pri_key: &RsaKey, random: &'a [u8]) -> RlsResult<RecordLayer<'a>> {
        self.derived.set_client_random(client_hello.client_random().as_ref().try_into()?);
        let mut record = RecordLayer {
            context_type: RecordType::HandShake,
            version: Version::TLS_1_2,
            len: 0,
            messages: vec![],
        };
        //server hello
        let mut server_hello = ServerHello::from_client_hello(client_hello)?;
        server_hello.set_random(random);
        self.set_by_server_hello(&server_hello)?;
        record.messages.push(Message::ServerHello(server_hello));
        //certificate
        let mut certificates = Certificates::default();
        for certificate in certificate.iter_mut() {
            certificates.add_certificate(certificate.as_der()?.as_slice());
        }
        record.messages.push(Message::Certificate(certificates));
        //server_key_exchange
        let mut server_key_exchange = ServerKeyExchange::default();
        let key = SecretKey::new(*server_key_exchange.hellman_param().named_curve())?;
        server_key_exchange.hellman_param_mut().set_pub_key(Buf::Vec(key.pub_key()?.to_vec()));
        self.secret_key = Some(key);
        let sign_data = self.gen_key_sign_data(&server_key_exchange);
        let signer = AlgorithmSigner::new_sign(pri_key.pkey(), server_key_exchange.hellman_param().signature_algorithm())?;
        server_key_exchange.hellman_param_mut().set_signature(Buf::Vec(signer.sign(&sign_data)?));
        self.exchange_pub_key = Bytes::new(server_key_exchange.hellman_param().pub_key().to_vec());
        self.named_curve = *server_key_exchange.hellman_param().named_curve();
        record.messages.push(Message::ServerKeyExchange(server_key_exchange));
        //server_hello_done
        record.messages.push(Message::ServerHelloDone(ServerHelloDone::new()));
        Ok(record)
    }

    ///#### tls Record结构-5bytes(头部)
    /// * aes-gcm: payload(8byte的explicit+16payload+16byte的tag)
    /// * chacha20_poly1305: payload(16payload+16byte tag)
    pub fn make_finish_message(&mut self, buffer: &mut [u8], server: bool) -> RlsResult<usize> {
        let session_hash = self.cipher_suite.current_session_hash()?;
        let finish = self.derived.make_finish(self.version, server, session_hash)?;
        if self.version == Version::TLS_1_3 { self.derived.make_application_traffic_secret(session_hash)?; }
        self.update_session(&finish)?;
        self.make_message(RecordType::HandShake, buffer, &finish)
    }

    pub fn verify_finish(&mut self, data: &[u8], server: bool) -> RlsResult<()> {
        if self.verify {
            let session_hash = self.cipher_suite.current_session_hash()?;
            let out = self.derived.make_finish(self.version, server, session_hash)?;
            if data != out { return Err(HandShakeError::VerifyFinishedFail.into()); }
        }
        self.update_session(data)?;
        Ok(())
    }


    pub fn make_message(&mut self, cty: RecordType, buffer: &mut [u8], payload: &[u8]) -> RlsResult<usize> {
        let aead = self.cipher_suite.aead().ok_or(RlsError::AeadNone)?;
        let buffer = RecordEncodeBuffer::new(cty, &self.version, buffer, payload, aead);
        self.write.encrypt(buffer)
    }

    pub fn read_message(&mut self, origin: &[u8], buffer: &mut [u8]) -> RlsResult<usize> {
        let aead = self.cipher_suite.aead().ok_or(RlsError::AeadNone)?;
        let buffer = RecordDecodeBuffer::from_buffer(origin, buffer, aead, &self.version)?;
        self.read.decrypt(buffer)
    }

    pub fn alpn(&self) -> Option<&ALPN> {
        self.alpn.as_ref()
    }

    pub fn update_session(&mut self, data: impl AsRef<[u8]>) -> RlsResult<()> {
        if self.mtls() || self.cipher_suite.hasher().is_none() {
            self.session_bytes.extend_from_slice(data.as_ref());
        }
        if self.cipher_suite.hasher().is_some() {
            self.cipher_suite.update(data)?;
        }
        Ok(())
    }

    pub fn cipher_suite(&self) -> &CipherSuite { &self.cipher_suite }

    pub fn mtls(&self) -> bool { self.mtls_hash.as_u16() != 0 }
    pub fn handle_mtls_client<W: WriteExt>(&mut self, writer: &mut W, key: &RsaKey) -> RlsResult<usize> {
        let mut cert_verify = CertificateVerify::default();
        cert_verify.set_hash(self.mtls_hash.as_u16().into());
        let signer = AlgorithmSigner::new_sign(key.pkey(), &self.mtls_hash)?;
        let sign = signer.sign(mem::take(&mut self.session_bytes))?;
        cert_verify.set_sign(&sign);
        let mut record = RecordLayer::handshake();
        record.messages.push(Message::CertificateVerify(cert_verify));
        record.write_to(writer, 1)
    }

    pub fn set_secret_keys(&mut self, keys: Vec<SecretKey>) {
        self.secret_keys = keys;
    }

    pub fn secret_keys(&self) -> &[SecretKey] { &self.secret_keys }

    pub fn version(&self) -> &Version { &self.version }
}