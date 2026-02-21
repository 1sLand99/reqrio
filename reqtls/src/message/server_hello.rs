use super::super::extend::Extension;
use super::super::message::HandshakeType;
use super::super::suite::CipherSuite;
use super::super::version::Version;
use crate::bytes::ByteRef;
use crate::error::RlsResult;
use crate::extend::alps::ALPS;
use crate::extend::ExtensionValue;
use crate::{ClientHello, ExtensionType, WriteExt, ALPN};

#[derive(Debug)]
pub struct ServerHello<'a> {
    handshake_type: HandshakeType,
    len: u32,
    version: Version,
    pub(crate) random: ByteRef<'a>,
    session_id_len: u8,
    session_id: ByteRef<'a>,
    pub cipher_suite: CipherSuite,
    compress_method: u8,
    extend_len: u16,
    extensions: Vec<Extension>,
}

impl<'a> Default for ServerHello<'a> {
    fn default() -> Self {
        ServerHello {
            handshake_type: HandshakeType::ServerHello,
            len: 0,
            version: Version::new(0),
            random: ByteRef::default(),
            session_id_len: 0,
            session_id: ByteRef::default(),
            cipher_suite: CipherSuite::new(0),
            compress_method: 0,
            extend_len: 0,
            extensions: vec![],
        }
    }
}

impl<'a> ServerHello<'a> {
    pub fn from_bytes(ht: HandshakeType, bytes: &'a [u8]) -> RlsResult<ServerHello<'a>> {
        let mut res = ServerHello::default();
        res.handshake_type = ht;
        res.len = u32::from_be_bytes([0, bytes[1], bytes[2], bytes[3]]);
        res.version = Version::new(u16::from_be_bytes([bytes[4], bytes[5]]));
        res.random = ByteRef::new(&bytes[6..38]);
        res.session_id_len = bytes[38];
        let index = 39 + res.session_id_len as usize;
        res.session_id = ByteRef::new(&bytes[39..index]);
        let v = u16::from_be_bytes([bytes[index], bytes[index + 1]]);
        res.cipher_suite = CipherSuite::new(v);
        res.compress_method = bytes[index + 2];
        res.extend_len = u16::from_be_bytes([bytes[index + 3], bytes[index + 4]]);
        res.extensions = Extension::from_bytes(&bytes[index + 5..index + 5 + res.extend_len as usize], true)?;
        Ok(res)
    }

    pub fn from_client_hello(mut client_hello: ClientHello) -> RlsResult<ServerHello<'a>> {
        let mut res = ServerHello::default();
        res.version = Version::TLS_1_2;
        // res.random = ByteRef::new(random);
        // res.session_id = ByteRef::new(session_id);
        res.cipher_suite = CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
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

    pub fn len(&self) -> usize {
        6 + self.random.len() + 1 + self.session_id.len() + 2 + 1 + 2 +
            self.extensions.iter().map(|x| x.len(true)).sum::<usize>()
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) {
        writer.write_u8(self.handshake_type as u8);
        writer.write_u32(self.len() as u32 - 4, true);
        writer.write_u16(self.version.into_inner());
        writer.write_slice(self.random.as_ref());
        writer.write_u8(self.session_id.len() as u8);
        writer.write_slice(self.session_id.as_ref());
        writer.write_u16(self.cipher_suite.into_inner());
        writer.write_u8(self.compress_method);
        let len = self.extensions.iter().map(|x| x.len(true)).sum::<usize>();
        writer.write_u16(len as u16);
        for extension in self.extensions {
            extension.write_to(writer, true)
        }
    }

    pub fn set_random(&mut self, random: &'a [u8]) {
        self.random = ByteRef::new(random);
    }

    pub fn set_session_id(&mut self, session_id: &'a [u8]) {
        self.session_id = ByteRef::new(session_id);
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

    pub fn len(&self) -> usize {
        4
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) {
        writer.write_u8(self.handshake_type as u8);
        writer.write_u32(self.len, true);
    }
}