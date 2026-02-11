use super::bytes::Bytes;
use super::cipher::iv::Iv;
use super::cipher::suite::CipherSuite;
use super::cipher::Cipher;
use super::extend::alps::ALPN;
use super::message::key_exchange::{NamedCurve, ServerKeyExchange};
use super::message::server_hello::{ServerHello, ServerHelloDone};
use super::prf::Prf;
use super::record::{RecordBuffer, RecordLayer, RecordType};
use super::version::Version;
use crate::boring::{certificate, AlgorithmSigner};
use crate::error::RlsResult;
use crate::secret::key::SharedKey;
use crate::*;
use std::fs::OpenOptions;
use std::io::Write;
use std::ops::Range;

pub struct Connection {
    client_random: Bytes,
    server_random: Bytes,
    read: Cipher,
    write: Cipher,
    use_ems: bool,
    master_secret: [u8; 48],
    named_curve: NamedCurve,
    exchange_pub_key: Bytes,
    alpn: Option<ALPN>,
    cipher_suite: CipherSuite,
    session_bytes: Vec<u8>,
    prf: Prf,
    certificates: Vec<Certificate>,
    shared_key: SharedKey,
    verify: bool,
    root_stores: &'static CertStore,
}
impl Default for Connection {
    fn default() -> Self {
        Connection {
            client_random: Bytes::none(),
            server_random: Bytes::none(),
            read: Cipher::none(),
            write: Cipher::none(),
            use_ems: false,
            master_secret: [0; 48],
            named_curve: NamedCurve::x25519,
            exchange_pub_key: Bytes::none(),
            alpn: None,
            cipher_suite: CipherSuite::new(0),
            session_bytes: vec![],
            prf: Prf::default(),
            certificates: vec![],
            shared_key: SharedKey::None,
            verify: false,
            root_stores: &certificate::ROOT_STORES,
        }
    }
}

impl Connection {
    pub fn with_client_random(mut self, client_random: Vec<u8>) -> Connection {
        self.client_random = Bytes::new(client_random);
        self
    }

    pub fn with_verify(mut self, verify: bool) -> Connection {
        self.verify = verify;
        self
    }

    pub fn disable_verify(mut self) -> Connection {
        self.verify = false;
        self
    }

    pub fn set_client_random(&mut self, client_random: Vec<u8>) {
        self.client_random = Bytes::new(client_random);
    }

    pub fn set_by_server_hello(&mut self, server_hello: ServerHello) -> RlsResult<()> {
        self.use_ems = server_hello.use_ems();
        self.alpn = server_hello.alpn();
        self.server_random = server_hello.random;
        self.cipher_suite = server_hello.cipher_suite;
        self.cipher_suite.init_aead_hasher()?;
        let hasher = self.cipher_suite.hasher().as_ref().ok_or(RlsError::HasherNone)?;
        self.prf = Prf::from_hasher(hasher);
        Ok(())
    }

    pub fn set_by_certificate(&mut self, certificate: Certificates, sni: &str) -> RlsResult<()> {
        for certificate in certificate.certificates() {
            self.certificates.push(Certificate::from_der(certificate.as_ref())?);
        }
        if !self.verify { return Ok(()); }
        self.root_stores.verify_cert(&self.certificates, sni)
    }

    fn gen_key_sign_data(&self, server_key: &ServerKeyExchange) -> Vec<u8> {
        let mut sign_data = vec![];
        sign_data.extend_from_slice(self.client_random.as_ref());
        sign_data.extend_from_slice(self.server_random.as_ref());
        sign_data.push(*server_key.hellman_param().curve_type() as u8);
        sign_data.extend(server_key.hellman_param().named_curve().as_bytes());
        sign_data.push(server_key.hellman_param().pub_key().len() as u8);
        sign_data.extend(server_key.hellman_param().pub_key().as_bytes());
        sign_data
    }

    pub fn set_by_server_exchange_key(&mut self, server_key: ServerKeyExchange) -> RlsResult<()> {
        if self.verify {
            let sign_data = self.gen_key_sign_data(&server_key);
            println!("{:?}", server_key.hellman_param().signature_algorithm());
            let signature = AlgorithmSigner::new_verify(self.certificates[0].pub_key()?, server_key.hellman_param().signature_algorithm())?;
            signature.verify(sign_data, server_key.hellman_param().signature().as_ref())?;
        }
        self.exchange_pub_key = server_key.hellman_param().pub_key().clone();
        self.named_curve = *server_key.hellman_param().named_curve();
        self.shared_key = SharedKey::new(&self.named_curve)?;
        Ok(())
    }

    pub fn set_by_client_exchange_key(&mut self, client_key: ClientKeyExchange) {
        self.exchange_pub_key = client_key.hellman_param().pub_key().clone();
    }

    pub fn pub_share_key(&mut self) -> RlsResult<Vec<u8>> {
        if let SharedKey::None = self.shared_key {
            self.shared_key = SharedKey::new_pre_master_secret()?;
            let rsa = RsaCipher::new(self.certificates[0].pub_key()?)?;
            return rsa.encrypt(self.shared_key.pub_key()?.as_slice(), false);
        }
        Ok(self.shared_key.pub_key()?.as_slice().to_vec())
    }

    pub fn make_cipher(&mut self, server: bool) -> RlsResult<()> {
        println!("{:?} {:?} {:?}", self.cipher_suite, self.cipher_suite.aead(), self.named_curve);
        let share_secret = self.shared_key.diffie_hellman(self.exchange_pub_key.as_ref())?;
        let (label, seed) = match self.use_ems {
            true => ("extended master secret", self.cipher_suite.current_session_hash()?.to_vec()),
            false => ("master secret", [self.client_random.as_bytes(), self.server_random.as_bytes()].concat())
        };
        self.prf.prf(&share_secret, label, &seed, &mut self.master_secret)?; //master" secret"
        let mut f = OpenOptions::new().create(true).append(true).open("2.log")?;
        f.write_all(format!("CLIENT_RANDOM {} {}\r\n", hex::encode(self.client_random.as_ref()), hex::encode(self.master_secret)).as_bytes())?;
        let aead = self.cipher_suite.aead().ok_or(RlsError::AeadNone)?;
        let block_size = (aead.key_len() + aead.fix_iv_len()) * 2 + aead.explicit_len();
        let mut key_block = vec![0; block_size];
        let seed = [self.server_random.as_bytes(), self.client_random.as_bytes()].concat();
        self.prf.prf(&self.master_secret, "key expansion", &seed, key_block.as_mut_slice())?;
        let (client_key, remain) = key_block.split_at(aead.key_len());
        let (server_key, remain) = remain.split_at(aead.key_len());
        let (client_iv, remain) = remain.split_at(aead.fix_iv_len());
        let (server_iv, explicit) = remain.split_at(aead.fix_iv_len());
        match server {
            true => {
                self.write.set_key(server_key, aead)?;
                self.write.set_iv(Iv::new(server_iv, vec![0; 8]));
                self.read.set_key(client_key, aead)?;
                self.read.set_iv(Iv::new(client_iv, vec![]));
            }
            false => {
                self.write.set_key(client_key, aead)?;
                self.write.set_iv(Iv::new(client_iv, explicit.to_vec()));
                self.read.set_key(server_key, aead)?;
                self.read.set_iv(Iv::new(server_iv, vec![]));
            }
        }

        Ok(())
    }

    pub fn gen_server_hello(&mut self, mut client_hello: ClientHello, certificate: &mut [Certificate], pri_key: &RsaKey) -> RlsResult<Vec<u8>> {
        self.set_client_random(client_hello.take_random());
        let server_hello = ServerHello::from_client_hello(client_hello)?;
        let server_hello_bytes = server_hello.as_bytes();
        self.update_session(&server_hello_bytes)?;
        self.set_by_server_hello(server_hello)?;

        let mut certificates = Certificates::default();
        for certificate in certificate.iter_mut() {
            certificates.add_certificate(certificate.as_der().as_slice());
        }
        let certificate_bytes = certificates.as_bytes();
        self.update_session(&certificate_bytes)?;

        let mut server_key_exchange = ServerKeyExchange::default();
        self.shared_key = SharedKey::new(server_key_exchange.hellman_param().named_curve())?;
        server_key_exchange.hellman_param_mut().set_pub_key(self.shared_key.pub_key()?.as_slice());
        let sign_data = self.gen_key_sign_data(&server_key_exchange);
        let signer = AlgorithmSigner::new_sign(pri_key.pkey(), server_key_exchange.hellman_param().signature_algorithm())?;
        server_key_exchange.hellman_param_mut().set_signature(Bytes::new(signer.sign(&sign_data)?));

        // let cert = certificate.first_mut().unwrap();
        // AlgorithmSigner::new_verify(cert.pub_key()?, server_key_exchange.hellman_param().signature_algorithm())?.verify(sign_data, server_key_exchange.hellman_param().signature().as_ref())?;
        self.exchange_pub_key = server_key_exchange.hellman_param().pub_key().clone();
        self.named_curve = *server_key_exchange.hellman_param().named_curve();
        let server_key_exchange_bytes = server_key_exchange.as_bytes();
        self.update_session(&server_key_exchange_bytes)?;

        let server_hello_done = ServerHelloDone::new();
        let server_hello_done_bytes = server_hello_done.as_bytes();
        self.update_session(&server_hello_done_bytes)?;


        let mut record = RecordLayer::default();
        record.version = Version::TLS_1_2;
        record.context_type = RecordType::HandShake;
        record.len = (server_hello_bytes.len() + certificate_bytes.len() + server_key_exchange_bytes.len() + server_hello_done_bytes.len()) as u16;
        let mut bytes = record.head_bytes();
        bytes.extend(record.len.to_be_bytes());
        bytes.extend(server_hello_bytes);
        bytes.extend(certificate_bytes);
        bytes.extend(server_key_exchange_bytes);
        bytes.extend(server_hello_done_bytes);
        Ok(bytes)
    }

    ///#### tls Record结构-5bytes(头部)
    /// * aes-gcm: payload(8byte的explicit+16payload+16byte的tag)
    /// * chacha20_poly1305: payload(16payload+16byte tag)
    pub fn make_finish_message(&mut self, buffer: &mut [u8], server: bool) -> RlsResult<usize> {
        let finish = self.make_verify_data(server)?;
        self.update_session(finish)?;
        self.make_message(RecordType::HandShake, buffer, &finish)
    }

    pub fn verify_finish(&mut self, data: &[u8], server: bool) -> RlsResult<()> {
        if !self.verify {
            self.update_session(data)?;
            return Ok(());
        }
        let out = self.make_verify_data(server)?;
        self.update_session(data)?;
        if data != out { return Err(RlsError::Currently("FinishVerifyFail".into())); }
        Ok(())
    }

    fn make_verify_data(&mut self, server: bool) -> RlsResult<[u8; 16]> {
        let mut finish = [0; 16];
        finish[0..4].copy_from_slice(&[0x14, 0x00, 0x0, 0xc]);
        let session_hash = self.cipher_suite.current_session_hash()?;
        self.prf.prf(&self.master_secret, if !server { "client finished" } else { "server finished" }, session_hash, &mut finish[4..16])?;
        Ok(finish)
    }

    pub fn make_message(&mut self, cty: RecordType, buffer: &mut [u8], payload: &[u8]) -> RlsResult<usize> {
        let aead = self.cipher_suite.aead().ok_or(RlsError::AeadNone)?;
        let mut buffer = RecordBuffer::from_buffer(aead, buffer);
        buffer.set_head(cty, Version::TLS_1_2);
        buffer.set_payload(payload);
        self.write.encrypt(buffer)
    }

    pub fn read_message<'a>(&mut self, layer: &'a mut RecordLayer<'a>) -> RlsResult<Range<usize>> {
        self.read.decrypt(layer, self.cipher_suite.aead().ok_or(RlsError::AeadNone)?)
    }

    pub fn alpn(&self) -> Option<&ALPN> {
        self.alpn.as_ref()
    }

    pub fn update_session(&mut self, data: impl AsRef<[u8]>) -> RlsResult<()> {
        if self.cipher_suite.hasher().is_none() {
            self.session_bytes.extend_from_slice(data.as_ref());
        } else {
            if !self.session_bytes.is_empty() {
                self.cipher_suite.update(&self.session_bytes)?;
                self.session_bytes.clear();
            }
            self.cipher_suite.update(data)?;
        }
        Ok(())
    }

    pub fn cipher_suite(&self) -> &CipherSuite { &self.cipher_suite }
}