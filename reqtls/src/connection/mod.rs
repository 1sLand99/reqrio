#[cfg(feature = "quic")]
mod quic;

use super::record::{RecordLayer, RecordType};
use super::suite::iv::Iv;
use super::suite::CipherSuite;
use super::suite::TlsCipher;
use super::version::Version;
use crate::boring::{certificate, AeadDir, AlgorithmSigner};
use crate::buffer::{Buf, CipherEncodeBuffer, TlsDecodeBuffer};
use crate::error::{HandShakeError, RlsResult};
use crate::key::{DerivedKey, KeyType, SecretKey, TlsSession};
use crate::message::{CompressedCertificate, EncryptedExtension, HandshakeType};
use crate::*;
#[cfg(feature = "quic")]
pub use quic::QUICConnection;
use std::collections::HashMap;
use std::mem;
use std::path::PathBuf;

pub struct Connection {
    pub(crate) recv_cipher: TlsCipher,
    pub(crate) send_cipher: TlsCipher,
    named_curve: NamedCurve,
    exchange_pub_key: Buf<'static>,
    alpn: Option<ALPN>,
    cipher_suite: &'static CipherSuite,
    session_bytes: Vec<u8>,
    pub(crate) derived: DerivedKey,
    certificates: Vec<Certificate>,
    secret_keys: HashMap<NamedCurve, SecretKey>,
    secret_key: Option<SecretKey>,
    verify: bool,
    root_stores: &'static CertStore,
    sig_alg: SignatureAlgorithm,
    mtls_hash: SignatureAlgorithm,
    mtls_enable: bool,
    version: Version,
    server: bool,
    hasher: Hasher,
}
impl Default for Connection {
    fn default() -> Self {
        Connection::new([0; 32], [0; 32], TlsSession::default(), None, false)
    }
}

impl Connection {
    const HRR_MAGIC: [u8; 32] = [207, 33, 173, 116, 229, 154, 97, 17, 190, 29, 140, 2, 30, 101, 184, 145, 194, 162, 17, 22, 122, 187, 140, 94, 7, 158, 9, 226, 200, 168, 51, 156];

    pub fn new(client_random: [u8; 32], server_random: [u8; 32], session: TlsSession, key_log: Option<PathBuf>, quic: bool) -> Connection {
        Connection {
            recv_cipher: TlsCipher::none(),
            send_cipher: TlsCipher::none(),
            named_curve: NamedCurve::X25519.into(),
            exchange_pub_key: Buf::Ref(&[]),
            alpn: None,
            cipher_suite: &CipherSuite::UNKNOWN,
            session_bytes: Vec::with_capacity(4096),
            derived: DerivedKey::new(client_random, server_random, session, key_log, quic),
            certificates: vec![],
            verify: false,
            root_stores: &certificate::ROOT_STORES,
            mtls_hash: SignatureAlgorithm::new(0),
            mtls_enable: false,
            version: Version::TLS_1_2,
            secret_keys: HashMap::new(),
            secret_key: None,
            server: false,
            hasher: Hasher::default(),
            sig_alg: SignatureAlgorithm::new(0),
        }
    }

    pub fn new_client(session: TlsSession, key_log: Option<PathBuf>, quic: bool) -> Connection {
        Connection::new(rand::random(), [0; 32], session, key_log, quic)
    }

    pub fn client_random(&self) -> &[u8] {
        &self.derived.client_random
    }

    pub fn with_verify(mut self, verify: bool) -> Connection {
        self.verify = verify;
        self
    }

    pub fn disable_verify(mut self) -> Connection {
        self.verify = false;
        self
    }

    pub fn with_mtls(mut self, mtls: bool) -> Connection {
        self.mtls_enable = mtls;
        self
    }

    pub fn hello_retry(&mut self, client_hello: &[u8]) -> RlsResult<()> {
        let cl = u32::from_be_bytes([0, self.session_bytes[1], self.session_bytes[2], self.session_bytes[3]]) as usize + 4;
        self.hasher.update(&self.session_bytes[..cl])?;
        let session_hash = self.hasher.current_hash()?;
        self.session_bytes[0] = HandshakeType::MessageHash as u8;
        self.session_bytes[1] = 0;
        self.session_bytes[2] = 0;
        self.session_bytes[3] = session_hash.len() as u8;
        self.session_bytes[4..session_hash.len() + 4].copy_from_slice(session_hash);
        let len = self.session_bytes.len();
        self.session_bytes.copy_within(cl..len, session_hash.len() + 4);
        unsafe { self.session_bytes.set_len(session_hash.len() + 4 + len - cl); }
        self.hasher = Hasher::default();
        self.update_session(client_hello)
    }

    pub fn set_by_server_hello(&mut self, server_hello: &ServerHello, version: Version) -> RlsResult<bool> {
        self.alpn = server_hello.alpn();
        self.derived.session.set_session_id(server_hello.session_id.as_ref());
        self.cipher_suite = server_hello.cipher_suite;
        self.hasher.init(self.cipher_suite.hash())?;
        if let Some(version) = server_hello.supported_version() {
            self.version = *version;
        } else { self.version = version; }
        if server_hello.random().as_ref() == Self::HRR_MAGIC { return Ok(true); }
        self.hasher.update(&self.session_bytes)?;
        #[cfg(feature = "log")]
        info!("[ParsedServerHello] Version: {:?} | CipherSuite: {} | Hasher: {:?} | AEAD: {:?}",
            self.version, self.cipher_suite.spec(), self.cipher_suite.hash(), self.cipher_suite.aead());
        self.derived.init(KeyType::Handshake, self.cipher_suite);
        self.derived.set_server_random(server_hello.random.as_ref().try_into()?);
        self.derived.use_ems=server_hello.use_ems();
        if Version::TLS_1_3 == self.version {
            let key_entry = server_hello.key_share_extend().ok_or(RlsError::MissingKeyEntry)?.key_entry();
            self.named_curve = key_entry.group();
            let secret_key = self.secret_keys.remove(&key_entry.group()).ok_or("secret not inited")?;
            let share_secret = secret_key.diffie_hellman(key_entry.key().as_ref())?;
            self.derived.make_handshake_traffic_secret(share_secret, self.hasher.current_hash()?)?;
            #[cfg(feature = "log")]
            info!("[ParsedServerHello] KeyShare={:?}; pubkey={}",key_entry.group(), key_entry.key().len());
            self.derived_key_cipher(KeyType::Handshake)?;
        }
        Ok(false)
    }

    pub(crate) fn derived_key_cipher(&mut self, typ: KeyType) -> RlsResult<()> {
        #[cfg(feature = "log")]
        trace!("[DerivedCipher] type={:?}; cipher={:?}; mac={:?}; veriosn={:?}",
            typ,self.cipher_suite.aead(),self.cipher_suite.mac_hash(),self.version);
        let key = self.derived.make_cipher_key(&self.version, typ)?;
        let sk = key.send_key(typ, self.server);
        self.send_cipher.set_key(sk, self.cipher_suite, AeadDir::Seal)?;
        self.send_cipher.set_iv(Iv::new(key.send_iv(typ, self.server)));
        let rk = key.recv_key(typ, self.server);
        self.recv_cipher.set_key(rk, self.cipher_suite, AeadDir::Open)?;
        self.recv_cipher.set_iv(Iv::new(key.recv_iv(typ, self.server)));
        Ok(())
    }

    pub fn set_by_encrypted_extension(&mut self, encrypted: &EncryptedExtension) {
        self.alpn = encrypted.alpn().cloned();
    }

    pub fn set_by_certificate(&mut self, certificate: Certificates, ext_cas: &[Certificate], sni: &str) -> RlsResult<()> {
        for certificate in certificate.certificates() {
            self.certificates.push(Certificate::from_der(certificate.as_ref())?);
        }
        if !self.verify { return Ok(()); };
        if self.version == Version::TLCP {
            self.certificates[0].verify_sni(sni)?;
            return Ok(());
        }
        self.root_stores.verify_cert(&mut self.certificates, ext_cas, sni)
    }

    pub fn set_by_compressed_certificate(&mut self, cc: CompressedCertificate<'_>, ext_cas: &[Certificate], sni: &str) -> RlsResult<()> {
        #[cfg(feature = "log")]
        debug!("[ParsedCompCert] method={}; size={}",cc.algorithm(), cc.compressed_data().len());
        match cc.algorithm() {
            CompressionMethod::BROTLI => {
                let data = coder::br_decompress(cc.compressed_data())?;
                let mut reader = Reader::from_slice(&data);
                let certs = Certificates::from_reader(&self.version, &mut reader, true)?;
                self.set_by_certificate(certs, ext_cas, sni)?;
                Ok(())
            }
            _ => panic!("unsupported compression method"),
        }
    }

    fn gen_key_sign_data(&mut self, server_key: &ServerKeyExchange, key: &mut Sm2Key) -> RlsResult<Vec<u8>> {
        match self.version {
            Version::TLCP => {
                let mut sign_data = Vec::with_capacity(1024);
                sign_data.extend_from_slice(&self.derived.client_random);
                sign_data.extend_from_slice(&self.derived.server_random);
                for certificate in self.certificates.iter_mut() {
                    let (pubkey, key_usage) = certificate.sm2_pub_key()?;
                    if key_usage & 0x80 == 0x80 && key.is_null() {
                        *key = Sm2Key::from_pub_key(pubkey.as_slice())?;
                    } else if key_usage & 0x20 == 0x20 {
                        let len = certificate.as_der()?.as_slice().len() as u32;
                        sign_data.extend_from_slice(&len.to_be_bytes()[1..]);
                        sign_data.extend_from_slice(certificate.as_der()?.as_slice());
                    }
                    if !key.is_null() && sign_data.len() > 64 { break; }
                }
                Ok(sign_data)
            }
            _ => {
                let mut sign_data = Vec::with_capacity(512);
                sign_data.extend_from_slice(&self.derived.client_random);
                sign_data.extend_from_slice(&self.derived.server_random);
                sign_data.push(*server_key.hellman_param().curve_type() as u8);
                sign_data.extend(server_key.hellman_param().named_curve().as_u16().to_be_bytes());
                sign_data.push(server_key.hellman_param().pub_key().len() as u8);
                sign_data.extend(server_key.hellman_param().pub_key().as_ref());
                Ok(sign_data)
            }
        }
    }

    pub fn verify_cert(&mut self, verify: CertificateVerify<'_>, server: bool) -> RlsResult<()> {
        #[cfg(feature = "log")]
        info!("[CertVerify] verify={}; server={}; algorithm={}", self.verify, server, verify.hash().spec());
        if !self.verify { return Ok(()); }
        let mut sign_data = Vec::with_capacity(256);
        sign_data.extend([0x20; 64]);
        match server {
            true => sign_data.extend_from_slice(b"TLS 1.3, server CertificateVerify"),
            false => sign_data.extend_from_slice(b"TLS 1.3, client CertificateVerify")
        }
        sign_data.push(0);
        sign_data.extend_from_slice(self.hasher.current_hash()?);
        let cert = self.certificates.first_mut().ok_or("missing cert")?;
        let signer = AlgorithmSigner::new_verify(cert.pub_key()?, verify.hash())?;
        signer.verify(sign_data, verify.sign().as_ref())?;
        Ok(())
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
        self.sig_alg = *server_key.hellman_param().signature_algorithm();
        self.named_curve = *server_key.hellman_param().named_curve();
        #[cfg(feature = "log")]
        info!("[ExchangeKey] algorithm={}; curve={:?}; verify={}", self.sig_alg.spec(), self.named_curve, self.verify);
        match (self.verify, self.version) {
            (true, Version::TLCP) => {
                let mut key = Sm2Key::none();
                let sign_data = self.gen_key_sign_data(&server_key, &mut key)?;
                key.verify_asn1(sign_data, server_key.hellman_param().signature().as_ref())?;
            }
            (true, _) => {
                let sign_data = self.gen_key_sign_data(&server_key, &mut Sm2Key::none())?;
                let signature = AlgorithmSigner::new_verify(self.certificates[0].pub_key()?, self.sig_alg)?;
                signature.verify(sign_data, server_key.hellman_param().signature().as_ref())?;
            }
            (_, _) => {}
        }
        self.exchange_pub_key = Buf::Vec(server_key.hellman_param().pub_key().to_vec());
        if self.version == Version::TLCP {
            self.secret_key = Some(SecretKey::new_pre_master_secret(&self.version)?)
        } else {
            self.secret_key = Some(SecretKey::new(self.named_curve)?);
        }
        self.secret_keys.clear();
        self.secret_keys.shrink_to_fit();
        Ok(())
    }

    pub fn set_by_session_ticket(&mut self, ticket: SessionTicket) {
        self.derived.session.set_ticket(ticket.tls_ticket().ticket().to_vec());
    }

    pub fn set_by_client_exchange_key(&mut self, client_key: ClientKeyExchange) {
        self.exchange_pub_key = Buf::Vec(client_key.hellman_param().pub_key().to_vec());
    }

    pub fn pub_share_key(&mut self) -> RlsResult<Buf<'_>> {
        if let Some(ref mut secret_key) = self.secret_key {
            if secret_key.named_curve() == NamedCurve::PRE_MASTER {
                debug_assert_eq!(self.version, Version::TLCP);
                let cert = self.certificates.iter_mut().find_map(|cert| {
                    let cert = cert.sm2_pub_key().ok().filter(|x| x.1 & 0x20 == 0x20);
                    cert.map(|x| x.0)
                }).ok_or(HandShakeError::MissingPubkey)?;
                let sm2_key = Sm2Key::from_pub_key(cert.as_slice())?;
                let pubkey = sm2_key.encrypt_premaster(secret_key.pub_key()?)?;
                return Ok(Buf::Vec(pubkey));
            }
            Ok(secret_key.pub_key()?)
        } else {
            debug_assert_eq!(self.version, Version::TLS_1_2);
            let key = SecretKey::new_pre_master_secret(&self.version)?;
            let rsa = RsaCipher::new(self.certificates[0].pub_key()?)?;
            let pub_key = Buf::Vec(rsa.encrypt(key.pub_key()?)?);
            self.secret_key = Some(key);
            Ok(pub_key)
        }
    }

    pub fn make_cipher(&mut self, recover: bool) -> RlsResult<()> {
        if matches!(self.version, Version::TLS_1_2|Version::TLCP) && !recover {
            let secret_key = self.secret_key.as_mut().ok_or("Invalid secret key")?;
            let share_secret = secret_key.diffie_hellman(self.exchange_pub_key.as_ref())?;
            self.derived.make_master(Version::TLS_1_2, share_secret, self.hasher.current_hash()?)?;
        }
        self.derived_key_cipher(KeyType::Application)?;
        Ok(())
    }

    pub fn gen_server_hello<'a>(&mut self, _record_version: Version, client_hello: ClientHello<'a>, certificate: &'a mut [Certificate], pri_key: &RsaKey, random: &'a [u8], alpn: ALPN) -> RlsResult<RecordLayer<'a>> {
        self.derived.set_client_random(client_hello.client_random().as_ref().try_into()?);
        let mut record = RecordLayer {
            content_type: RecordType::HandShake,
            version: Version::TLS_1_2,
            len: 0,
            messages: vec![],
        };
        //server hello
        let mut server_hello = ServerHello::from_client_hello(client_hello, alpn)?;
        server_hello.set_random(random);
        self.set_by_server_hello(&server_hello, Version::TLS_1_2)?;
        record.messages.push(Message::new_parsed(MessageParsed::ServerHello(server_hello)));
        //certificate
        let mut certificates = Certificates::default();
        for certificate in certificate.iter_mut() {
            certificates.add_certificate(certificate.as_der()?.as_slice());
        }
        record.messages.push(Message::new_parsed(MessageParsed::Certificate(certificates)));
        //server_key_exchange
        let mut server_key_exchange = ServerKeyExchange::default();
        let key = SecretKey::new(*server_key_exchange.hellman_param().named_curve())?;
        server_key_exchange.hellman_param_mut().set_pub_key(Buf::Vec(key.pub_key()?.to_vec()));
        self.secret_key = Some(key);
        let sign_data = self.gen_key_sign_data(&server_key_exchange, &mut Sm2Key::none())?;
        let signer = AlgorithmSigner::new_sign(pri_key.pkey(), server_key_exchange.hellman_param().signature_algorithm())?;
        server_key_exchange.hellman_param_mut().set_signature(Buf::Vec(signer.sign(&sign_data)?));
        self.exchange_pub_key = Buf::Vec(server_key_exchange.hellman_param().pub_key().to_vec());
        self.named_curve = *server_key_exchange.hellman_param().named_curve();
        record.messages.push(Message::new_parsed(MessageParsed::ServerKeyExchange(server_key_exchange)));
        //server_hello_done
        record.messages.push(Message::new_parsed(MessageParsed::ServerHelloDone(ServerHelloDone::new())));
        self.server = true;
        Ok(record)
    }

    ///#### tls Record结构-5bytes(头部)
    /// * aes-gcm: payload(8byte的explicit+16payload+16byte的tag)
    /// * chacha20_poly1305: payload(16payload+16byte tag)
    pub fn make_finish_message(&mut self, buffer: &mut [u8], server: bool) -> RlsResult<usize> {
        let session_hash = self.hasher.current_hash()?;
        let finish = self.derived.make_finish(self.version, server, session_hash)?;
        if self.version == Version::TLS_1_3 { self.derived.make_application_traffic_secret(session_hash)?; }
        self.update_session(&finish)?;
        if self.derived.quic {
            buffer[..finish.len()].copy_from_slice(finish.as_slice());
            Ok(finish.len())
        } else {
            self.make_message(RecordType::HandShake, buffer, &finish)
        }
    }

    pub fn verify_finish(&mut self, data: &[u8], server: bool) -> RlsResult<()> {
        if self.verify {
            let session_hash = self.hasher.current_hash()?;
            let out = self.derived.make_finish(self.version, server, session_hash)?;
            if data != out { return Err(HandShakeError::VerifyFinishedFail.into()); }
        }
        self.update_session(data)?;
        Ok(())
    }


    pub fn make_message(&mut self, cty: RecordType, buffer: &mut [u8], payload: &[u8]) -> RlsResult<usize> {
        if buffer.len() < 5 + payload.len() {
            return Err(BufferError::CapacityTooSmall {
                needed: 5 + payload.len(),
                current: buffer.len(),
                file: file!(),
                line: line!(),
            }.into());
        }
        let buffer = CipherEncodeBuffer::new_tls(cty, buffer, payload, self.cipher_suite);
        self.send_cipher.encrypt(None, buffer)
    }

    pub fn read_message(&mut self, origin: &[u8], buffer: &mut [u8]) -> RlsResult<usize> {
        let buffer = TlsDecodeBuffer::from_buffer(origin, buffer, self.cipher_suite)?;
        self.recv_cipher.decrypt(None, buffer)
    }

    pub fn alpn(&self) -> Option<&ALPN> {
        self.alpn.as_ref()
    }

    pub fn update_session(&mut self, data: impl AsRef<[u8]>) -> RlsResult<()> {
        // println!("update session: {} {:x?}", data.as_ref().len(), data.as_ref());
        if self.mtls_enable || !self.hasher.inited() {
            self.session_bytes.extend_from_slice(data.as_ref());
        }
        if self.hasher.inited() {
            self.hasher.update(data)?;
        }
        Ok(())
    }

    pub fn session_bytes(&self) -> &[u8] { &self.session_bytes }
    pub fn cipher_suite(&self) -> &'static CipherSuite { self.cipher_suite }
    pub fn session(&self) -> &TlsSession { &self.derived.session }
    pub fn server(&self) -> bool { self.server }
    pub fn handle_mtls_client(&mut self, writer: &mut Writer, key: &RsaKey) -> RlsResult<()> {
        let mut cert_verify = CertificateVerify::default();
        cert_verify.set_hash(self.mtls_hash.as_u16().into());
        let signer = AlgorithmSigner::new_sign(key.pkey(), &self.mtls_hash)?;
        let sign = signer.sign(mem::take(&mut self.session_bytes))?;
        cert_verify.set_sign(&sign);
        let mut record = RecordLayer::handshake(self.version);
        record.messages.push(Message::new_parsed(MessageParsed::CertificateVerify(cert_verify)));
        record.write_to(writer, KeyExchangeAlg::NULL)
    }

    pub fn set_secret_keys(&mut self, keys: HashMap<NamedCurve, SecretKey>) {
        self.secret_keys = keys;
    }

    pub fn secret_keys_mut(&mut self) -> &mut HashMap<NamedCurve, SecretKey> {
        &mut self.secret_keys
    }

    pub fn secret_keys(&self) -> &HashMap<NamedCurve, SecretKey> {
        &self.secret_keys
    }

    pub fn secret_key(&self) -> &Option<SecretKey> {
        &self.secret_key
    }

    pub fn named_curve(&self) -> &NamedCurve { &self.named_curve }

    pub fn version(&self) -> &Version { &self.version }

    pub fn sig_alg(&self) -> &SignatureAlgorithm { &self.sig_alg }
}


#[cfg(test)]
mod tests {
    use crate::boring::AeadDir;
    use crate::buffer::{CipherEncodeBuffer, TlsDecodeBuffer};
    use crate::error::RlsResult;
    use crate::suite::iv::Iv;
    use crate::{AeadCtx, CipherSuite, RecordType, Version};
    use std::os::raw::c_void;
    use std::ptr::{null, null_mut};

    #[repr(C)]
    struct TlsSession {
        ticket_len: usize,
        ticket: *const u8,
        session_id_len: u8,
        session_id: *const u8,
        master_secret: [u8; 48],
    }

    #[repr(C)]
    struct DerivedKey {
        session: TlsSession,
        client_random: [u8; 32],
    }

    #[repr(C)]
    struct Connection {
        derived: DerivedKey,
        secrets: *mut c_void,
        encryptor: AeadCtx,
        decryptor: AeadCtx,
        suite: &'static CipherSuite,
    }

    impl Connection {
        fn read_message(&mut self, origin: &[u8], out: &mut [u8], iv: &Iv, seq: Option<u64>) -> RlsResult<usize> {
            let mut buffer = TlsDecodeBuffer::from_buffer(origin, out, self.suite)?;
            let seq_num = if let Some(seq) = seq { seq } else { self.decryptor.seq };
            let aad = buffer.aad(seq_num)?;
            let nonce = buffer.nonce(iv, seq_num);
            // println!("seq: {}; aad: {:x?}; nonce: {:?}", seq_num, add, nonce);
            let len = self.decryptor.open(&nonce, &aad, &mut buffer)?;
            if seq.is_none() { self.decryptor.seq += 1 }
            Ok(len)
        }

        fn write_message(&mut self, rt: RecordType, origin: &[u8], out: &mut [u8], iv: &Iv, seq: Option<u64>) -> RlsResult<usize> {
            let mut buffer = CipherEncodeBuffer::new_tls(rt, out, origin, self.suite);
            let seq_num = if let Some(seq) = seq { seq } else { self.encryptor.seq };
            let aad = buffer.aad(seq_num);
            let nonce = iv.as_array(seq_num, None);
            buffer.add_explicit_iv(&nonce);
            // println!("seq: {}; aad: {:x?}; nonce: {:?}", seq_num, aad, nonce);
            self.encryptor.seal(&nonce, &aad, &mut buffer)?;
            if seq.is_none() { self.encryptor.seq += 1; }
            Ok(buffer.record_len())
        }
    }

    fn test_encrypt(key: &[u8], suite: &'static CipherSuite, iv: Iv, en: &[u8]) {
        let mut connection = Connection {
            derived: DerivedKey {
                session: TlsSession {
                    ticket_len: 0,
                    ticket: null(),
                    session_id_len: 0,
                    session_id: null(),
                    master_secret: [0; 48],
                },
                client_random: [0; 32],
            },
            secrets: null_mut(),
            encryptor: AeadCtx::new(*suite.aead(), AeadDir::Seal).init(key).unwrap(),
            decryptor: AeadCtx::new(*suite.aead(), AeadDir::Open).init(key).unwrap(),
            suite,
        };
        let payload = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 34, 3, 3, 3];
        let mut out = [0; 1024];
        let len = connection.write_message(RecordType::HandShake, &payload, &mut out, &iv, None).unwrap();
        assert_eq!(&out[..len], en);

        let mut decoded = [0; 80];
        let mut len = connection.read_message(&out[..len], &mut decoded, &iv, None).unwrap();
        if suite.version == &Version::TLS_1_3 { len -= 1; }
        assert_eq!(&decoded[..len], payload);
    }


    #[test]
    fn test_connection() {
        let suite = &CipherSuite::TLS_AES_128_GCM_SHA256;
        let key = [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        let iv = Iv::new(&[1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4]);
        let en = [23, 3, 3, 0, 33, 34, 40, 91, 27, 49, 27, 234, 48, 61, 80, 240, 83, 57, 50, 173, 18, 215, 175, 31, 86, 15, 170, 121, 14, 214, 229, 157, 92, 45, 134, 62, 241, 235];
        test_encrypt(&key, suite, iv, &en);


        let suite = &CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA;
        let mut mac_key = vec![12; suite.mac_key_size];
        mac_key.extend([1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8]);
        let iv = Iv::new(&[1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8]);
        let en = [22, 3, 3, 0, 64, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 206, 174, 82, 144, 162, 110, 228, 50, 236, 145, 88, 67, 130, 252, 202, 24, 27, 211, 112, 165, 77, 208, 61, 245, 177, 74, 121, 201, 13, 139, 77, 138, 249, 229, 227, 166, 194, 52, 189, 241, 222, 162, 0, 251, 58, 226, 9, 63];
        test_encrypt(&mac_key, suite, iv, &en);

        let suite = &CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA256;
        let mut mac_key = vec![12; suite.mac_key_size];
        mac_key.extend([1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8]);
        let iv = Iv::new(&[1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8]);
        let en = [22, 3, 3, 0, 80, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 29, 210, 41, 29, 168, 173, 203, 170, 224, 45, 110, 107, 227, 240, 203, 36, 83, 152, 13, 240, 33, 31, 255, 32, 130, 27, 164, 212, 181, 49, 82, 194, 45, 165, 174, 78, 135, 40, 209, 43, 152, 115, 18, 62, 249, 120, 250, 211, 76, 205, 68, 187, 65, 233, 12, 243, 36, 90, 202, 83, 240, 2, 66, 29];
        test_encrypt(&mac_key, suite, iv, &en);


        let suite = &CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384;
        let mut mac_key = vec![12; suite.mac_key_size];
        mac_key.extend([1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8]);
        let iv = Iv::new(&[1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8]);
        let en = [22, 3, 3, 0, 96, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 29, 210, 41, 29, 168, 173, 203, 170, 224, 45, 110, 107, 227, 240, 203, 36, 88, 19, 168, 94, 92, 196, 205, 85, 207, 171, 128, 243, 140, 155, 132, 219, 46, 163, 37, 192, 137, 243, 11, 54, 186, 7, 106, 84, 73, 57, 240, 54, 21, 24, 229, 49, 75, 248, 187, 83, 119, 59, 42, 138, 145, 251, 110, 138, 132, 1, 18, 241, 53, 8, 132, 204, 209, 1, 197, 246, 216, 9, 55, 48];
        test_encrypt(&mac_key, suite, iv, &en);

        let suite = &CipherSuite::ECC_SM4_CBC_SM3;
        let mut mac_key = vec![12; suite.mac_key_size];
        mac_key.extend([1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8]);
        let iv = Iv::new(&[1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8]);
        let en = [22, 1, 1, 0, 80, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 198, 14, 19, 241, 183, 40, 82, 246, 189, 252, 121, 16, 190, 240, 95, 119, 196, 14, 130, 24, 130, 104, 168, 11, 212, 183, 172, 109, 10, 147, 121, 104, 165, 193, 48, 97, 205, 97, 245, 216, 86, 25, 229, 237, 236, 10, 247, 24, 137, 39, 196, 218, 125, 105, 75, 180, 126, 4, 204, 216, 153, 88, 207, 149];
        test_encrypt(&mac_key, suite, iv, &en);
    }
}