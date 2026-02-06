use super::super::bytes::Bytes;
use super::super::cipher::suite::CipherSuite;
use super::super::extend::alps::ALPN;
use super::super::extend::Extension;
use super::super::message::HandshakeType;
use super::super::version::Version;
use crate::cipher::suite::CipherSuiteKind;
use crate::error::RlsResult;
use crate::extend::alps::ALPS;
use crate::extend::ExtensionValue;
use crate::{rand, ClientHello, ExtensionType};

#[derive(Debug)]
pub struct ServerHello {
    handshake_type: HandshakeType,
    len: u32,
    version: Version,
    pub(crate) random: Bytes,
    session_id_len: u8,
    session_id: Bytes,
    pub cipher_suite: CipherSuite,
    compress_method: u8,
    extend_len: u16,
    extensions: Vec<Extension>,
}

impl Default for ServerHello {
    fn default() -> Self {
        ServerHello {
            handshake_type: HandshakeType::ServerHello,
            len: 0,
            version: Version::new(0),
            random: Bytes::new(vec![]),
            session_id_len: 0,
            session_id: Bytes::new(vec![]),
            cipher_suite: CipherSuite::new(0),
            compress_method: 0,
            extend_len: 0,
            extensions: vec![],
        }
    }
}

impl ServerHello {
    pub fn from_bytes(ht: HandshakeType, bytes: &[u8]) -> RlsResult<ServerHello> {
        let mut res = ServerHello::default();
        res.handshake_type = ht;
        res.len = u32::from_be_bytes([0, bytes[1], bytes[2], bytes[3]]);
        res.version = Version::new(u16::from_be_bytes([bytes[4], bytes[5]]));
        res.random = Bytes::new(bytes[6..38].to_vec());
        res.session_id_len = bytes[38];
        let index = 39 + res.session_id_len as usize;
        res.session_id = Bytes::new(bytes[39..index].to_vec());
        let v = u16::from_be_bytes([bytes[index], bytes[index + 1]]);
        res.cipher_suite = CipherSuite::new(v);
        res.compress_method = bytes[index + 2];
        res.extend_len = u16::from_be_bytes([bytes[index + 3], bytes[index + 4]]);
        res.extensions = Extension::from_bytes(&bytes[index + 5..index + 5 + res.extend_len as usize], true)?;
        Ok(res)
    }

    pub fn from_client_hello(mut client_hello: ClientHello) -> RlsResult<ServerHello> {
        let mut res = ServerHello::default();
        res.version = Version::TLS_1_2;
        res.random = Bytes::new(rand::random::<[u8; 32]>().to_vec());
        res.session_id = Bytes::new(rand::random::<[u8; 32]>().to_vec());
        res.cipher_suite = CipherSuite::new(CipherSuiteKind::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 as u16);
        for extension in client_hello.take_extensions() {
            match *extension.extension_type() {
                ExtensionType::SignatureAlgorithms => {
                    // let mut signature = SignatureAlgorithms::new();
                    // signature.push_hash(SignatureAlgorithm::RSA_PKCS1_SHA256);
                    // res.extensions.push(Extension::new(ExtensionType::SignatureAlgorithms, ExtensionValue::SignatureAlgorithms(signature)));
                }
                // ExtensionType::SignedCertificateTimestamp => res.extensions.push(extension),
                ExtensionType::EcPointFormats => {
                    // let mut ec_point_formats = EcPointFormats::new();
                    // ec_point_formats.add_format(EcPointFormat::UNCOMPRESSED);
                    // res.extensions.push(Extension::new(ExtensionType::EcPointFormats, ExtensionValue::EcPointFormats(ec_point_formats)));
                }
                ExtensionType::ApplicationLayerProtocolNegotiation => {
                    let mut alps = ALPS::new();
                    alps.add_alpn(ALPN::Http11);
                    res.extensions.push(Extension::new(ExtensionType::ApplicationLayerProtocolNegotiation, ExtensionValue::ApplicationLayerProtocolNegotiation(alps)));
                }
                ExtensionType::ExtendMasterSecret => res.extensions.push(extension),
                ExtensionType::SupportedVersions => {
                    // let mut version = SupportVersions::new();
                    // version.push(Version::TLS_1_2);
                    // res.extensions.push(Extension::new(ExtensionType::SupportedVersions, ExtensionValue::SupportedVersions(version)));
                }
                ExtensionType::SupportedGroup => {
                    // let mut groups = SupportedGroups::new();
                    // groups.add_group(GroupType::X25519);
                    // res.extensions.push(Extension::new(ExtensionType::SupportedGroup, ExtensionValue::SupportedGroups(groups)));
                }
                ExtensionType::RenegotiationInfo => res.extensions.push(extension),
                ExtensionType::ServerName => {}
                ExtensionType::StatusRequest => res.extensions.push(extension),
                ExtensionType::SessionTicket => res.extensions.push(extension),
                _ => {}
            }
        }
        Ok(res)
    }

    pub fn use_ems(&self) -> bool {
        self.extensions.iter().any(|x| x.extension_type() == &ExtensionType::ExtendMasterSecret)
    }

    pub fn alpn(&self) -> Option<ALPN> {
        let extend = self.extensions.iter().find(|x| x.alps().is_some())?;
        let protocol = extend.alps()?;
        let alpn = protocol.values().first()?.clone();
        Some(alpn)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut res = vec![self.handshake_type.as_u8(), 0, 0, 0];
        res.extend(self.version.as_bytes());
        res.extend(self.random.as_bytes());
        res.push(self.session_id.len() as u8);
        res.extend(self.session_id.as_bytes());
        res.extend(self.cipher_suite.as_bytes());
        res.push(self.compress_method);
        let mut ebs = vec![];
        for extension in &self.extensions {
            ebs.extend(extension.as_bytes(true));
        };
        res.extend((ebs.len() as u16).to_be_bytes());
        res.extend(ebs);
        let len = (res.len() - 4) as u32;
        res[1..4].copy_from_slice(len.to_be_bytes()[1..].as_ref());
        res
    }

    pub fn len(&self) -> u32 {
        self.len
    }
}

#[derive(Debug)]
pub struct ServerHelloDone {
    handshake_type: HandshakeType,
    len: u32,
}

impl ServerHelloDone {
    pub fn new() -> ServerHelloDone {
        ServerHelloDone {
            handshake_type: HandshakeType::ServerHelloDone,
            len: 0,
        }
    }

    pub fn from_bytes(ht: HandshakeType, bytes: &[u8]) -> RlsResult<ServerHelloDone> {
        let mut res = ServerHelloDone::new();
        res.handshake_type = ht;
        res.len = u32::from_be_bytes([0, bytes[1], bytes[2], bytes[3]]);
        Ok(res)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut res = vec![self.handshake_type.as_u8()];
        res.extend_from_slice(&self.len.to_be_bytes()[1..]);
        res
    }

    pub fn len(&self) -> u32 {
        self.len
    }
}