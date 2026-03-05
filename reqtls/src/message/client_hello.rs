use super::super::suite::CipherSuite;
use super::super::extend::Extension;
use super::super::version::Version;
use super::HandshakeType;
use crate::boring::hash;
use crate::bytes::ByteRef;
use crate::error::RlsResult;
use crate::extend::alps::ALPS;
use crate::extend::ExtensionType;
use crate::{rand, WriteExt};
use std::mem;


#[derive(Debug)]
pub struct ClientHello<'a> {
    handshake_type: HandshakeType,
    len: u32,
    version: Version,
    random: ByteRef<'a>,
    session_id_len: u8,
    session_id: ByteRef<'a>,
    cipher_suites_len: u16,
    cipher_suites: Vec<CipherSuite>,
    compress_method_len: u8,
    compress_method: ByteRef<'a>,
    extend_len: u16,
    extensions: Vec<Extension>,
}

impl<'a> Default for ClientHello<'a> {
    fn default() -> Self {
        ClientHello {
            handshake_type: HandshakeType::ClientHello,
            len: 0,
            version: Version::new(0),
            random: ByteRef::default(),
            session_id_len: 0,
            session_id: ByteRef::default(),
            cipher_suites_len: 0,
            cipher_suites: vec![],
            compress_method_len: 0,
            compress_method: ByteRef::default(),
            extend_len: 0,
            extensions: vec![],
        }
    }
}

impl<'a> ClientHello<'a> {
    pub fn random() -> ClientHello<'a> {
        let mut res = ClientHello {
            version: Version::TLS_1_0,
            cipher_suites: vec![
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                //ecdsa
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            ],
            random: ByteRef::new(&[0; 32]),
            session_id:ByteRef::new(&[0; 32]),
            compress_method: ByteRef::new(&[0]),
            extensions: vec![
                Extension::from_type(ExtensionType::SignatureAlgorithms),
                Extension::from_type(ExtensionType::SupportedGroup),
                Extension::from_type(ExtensionType::CompressionCertificate),
                Extension::from_type(ExtensionType::SupportedVersions),
                Extension::from_type(ExtensionType::ApplicationLayerProtocolNegotiation),
                Extension::from_type(ExtensionType::ServerName),
                Extension::from_type(ExtensionType::EcPointFormats),
                Extension::from_type(ExtensionType::RenegotiationInfo),
                Extension::from_type(ExtensionType::ExtendMasterSecret),
                // Extension::from_type(ExtensionType::SignedCertificateTimestamp),
                // Extension::from_type(ExtensionType::SessionTicket)
            ],
            ..Default::default()
        };
        let suite_all = CipherSuite::SUITES;
        while res.cipher_suites.len() < 12 {
            let index = rand::random::<usize>() % suite_all.len();
            let suite = CipherSuite::new(suite_all[index]);
            if res.cipher_suites.contains(&suite) { continue; }
            res.cipher_suites.push(suite);
        }
        res
    }

    pub fn from_bytes(ht: HandshakeType, bytes: &'a [u8]) -> RlsResult<ClientHello<'a>> {
        let mut res = ClientHello::default();
        res.handshake_type = ht;
        res.len = u32::from_be_bytes([0, bytes[1], bytes[2], bytes[3]]);
        res.version = Version::new(u16::from_be_bytes([bytes[4], bytes[5]]));
        res.random = ByteRef::new(&bytes[6..38]);
        res.session_id_len = bytes[38];
        let index = 39 + res.session_id_len as usize;
        if index > bytes.len() { println!("{:x?}", bytes); }
        res.session_id = ByteRef::new(&bytes[39..index]);
        res.cipher_suites_len = u16::from_be_bytes([bytes[index], bytes[index + 1]]);
        res.cipher_suites = CipherSuite::from_bytes(&bytes[index + 2..index + 2 + res.cipher_suites_len as usize])?;
        let index = index + res.cipher_suites_len as usize + 2;
        res.compress_method_len = bytes[index];
        res.compress_method = ByteRef::new(&bytes[index + 1..index + 1 + res.compress_method_len as usize]);
        let index = index + res.compress_method_len as usize + 1;
        res.extend_len = u16::from_be_bytes([bytes[index], bytes[index + 1]]);
        res.extensions = Extension::from_bytes(&bytes[index + 2..index + 2 + res.extend_len as usize], false)?;
        // println!("{}", res.ja3());
        // println!("{}", res.ja4());
        Ok(res)
    }

    pub fn is_empty(&self) -> bool { self.len() == 0 }

    pub fn len(&self) -> usize {
        6 + self.random.len() + 1 + self.session_id.len() + 2 +
            self.cipher_suites.len() * 2 + 1 + self.compress_method.len() + 2
            + self.extensions.iter().map(|x| x.len(false)).sum::<usize>()
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) {
        writer.write_u8(self.handshake_type as u8);
        writer.write_u32(self.len() as u32 - 4, true);
        writer.write_u16(self.version.into_inner());
        writer.write_slice(self.random.as_ref());
        writer.write_u8(self.session_id.len() as u8);
        writer.write_slice(self.session_id.as_ref());
        let len = self.cipher_suites.iter().map(|_| 2).sum::<usize>();
        writer.write_u16(len as u16);
        for cipher_suite in self.cipher_suites {
            writer.write_u16(cipher_suite.into_inner());
        }
        writer.write_u8(self.compress_method.len() as u8);
        writer.write_slice(self.compress_method.as_ref());
        let len = self.extensions.iter().map(|x| x.len(false)).sum::<usize>();
        writer.write_u16(len as u16);
        for extension in self.extensions {
            extension.write_to(writer, false);
        }
    }

    pub fn client_random(&mut self) -> &ByteRef<'a> { &self.random }

    ///### ja3计算方式为
    /// version+','+cipher_suite(u16)+','+extend_type(u16)+','+supported_groud值(u16)+','+ec_point_format(u8)
    /// tls1.3中移除了ec_point_format
    pub fn ja3(&self) -> String {
        //[JA3 Fullstring:
        // 771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,51-35-65281-0-23-17613-18-5-65037-43-27-13-10-11-45-16,4588-29-23-24,0]
        // 771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,51-35-65281-0-23-17613-18-5-65037-43-27-13-10-11-45-16,4588-29-23-24,0
        let ver = self.version.as_u16();
        let suite = self.cipher_suites.iter().filter_map(|x| if x.is_reserved() { None } else { Some(x.as_u16().to_string()) }).collect::<Vec<_>>();
        let ext = self.extensions.iter().filter_map(|x| if x.extension_type().is_reserved() { None } else { Some(x.extension_type().as_u16().to_string()) }).collect::<Vec<_>>();
        let extend = self.extensions.iter().find(|x| x.supported_groups().is_some());
        let group = if let Some(extend) = extend && let Some(group) = extend.supported_groups() {
            group.values().iter().filter_map(|x| if x.is_reserved() { None } else { Some(x.as_u16().to_string()) }).collect::<Vec<_>>()
        } else { vec![] };
        let extend = self.extensions.iter().find(|x| x.ex_point_formats().is_some());
        let formats = if let Some(extend) = extend && let Some(formats) = extend.ex_point_formats() {
            formats.formats().iter().map(|x| x.clone().into_inner().to_string()).collect::<Vec<_>>()
        } else {
            vec![]
        };
        let ja3_str = format!("{},{},{},{},{}", ver, suite.join("-"), ext.join("-"), group.join("-"), formats.join("-"));
        println!("{}", ja3_str);
        hex::encode(hash::md5(ja3_str).unwrap())
    }

    ///### ja4计算方式为
    /// 't'+version+'d'+len(cipher_suites)+len(extensions)+alpn+'_'+cipher_suite(u16)+','+ec_point_format(u8)
    /// tls1.3中移除了ec_point_format
    pub fn ja4(&self) -> String {
        let ver = self.extensions.iter().find(|x| x.extension_type() == &ExtensionType::SupportedVersions);
        let ver = ver.map(|ext| {
            let versions = ext.supported_versions()?.versions();
            let vers = versions.iter().filter(|x| x.is_reverse()).next()?;
            Some(vers.as_ja4_str())
        }).unwrap_or(Some("00")).unwrap_or("00");
        let mut suite = self.cipher_suites.iter().filter_map(|x| if x.is_reserved() {
            None
        } else {
            Some(x.as_u16())
        }).collect::<Vec<_>>();
        suite.sort();
        let mut exts = self.extensions.iter().filter_map(|x| if x.extension_type().is_reserved() {
            None
        } else if x.alps().is_some() {
            None
        } else if x.server_name().is_some() {
            None
        } else {
            Some(x.extension_type().as_u16())
        }).collect::<Vec<_>>();
        exts.sort();
        let ext = self.extensions.iter().find(|x| x.alps().is_some());
        let alps = ext.map(|ext| Some(ext.alps()?.values().get(0)?.value())).unwrap_or(Some("00")).unwrap_or("00");
        let ext = self.extensions.iter().find(|x| x.signature_algorithms().is_some());
        let sign_algo = ext.map(|x| Some(x.signature_algorithms()?.hashes().iter().map(|x| x.as_u16()).collect::<Vec<_>>()));
        let sign_algo = sign_algo.unwrap_or(Some(vec![])).unwrap_or(vec![]);
        let suite_str = suite.iter().map(|x| hex::encode(x.to_be_bytes())).collect::<Vec<_>>().join(",");
        println!("{}", suite_str);
        let suit_hash = hex::encode(hash::sha256(suite_str).unwrap());
        let c = format!("{}_{}", exts.iter().map(|x| hex::encode(x.to_be_bytes())).collect::<Vec<_>>().join(","),
                        sign_algo.iter().map(|x| hex::encode(x.to_be_bytes())).collect::<Vec<_>>().join(","));
        println!("{}", c);
        let c_hash = hex::encode(hash::sha256(c).unwrap());

        format!("t{}d{:.2}{:02}{}_{}_{}", ver, suite.len(), exts.len(), alps, &suit_hash[..12], &c_hash[..12])
    }

    pub fn set_random(&mut self, random: &'a [u8]) {
        self.random = ByteRef::new(random);
    }

    pub fn set_session_id(&mut self, session_id: &'a [u8]) {
        self.session_id = ByteRef::new(session_id);
    }

    pub fn set_server_name(&mut self, server_name: &str) {
        let extend = self.extensions.iter_mut().find(|x| x.extension_type() == &ExtensionType::ServerName);
        match extend {
            None => {
                let mut ext = Extension::from_type(ExtensionType::ServerName);
                ext.set_server_name(server_name);
                self.extensions.push(ext);
            }
            Some(ext) => ext.set_server_name(server_name),
        }
    }

    pub fn set_version(&mut self, version: Version) {
        self.version = version;
    }

    pub fn set_cipher_suites(&mut self, suites: Vec<CipherSuite>) {
        self.cipher_suites = suites;
    }

    pub fn set_extension(&mut self, extension: Vec<Extension>) {
        self.extensions = extension;
    }

    pub fn server_name(&self) -> Option<&str> {
        let extension = self.extensions.iter().find(|x| x.extension_type() == &ExtensionType::ServerName)?;
        Some(extension.server_name()?.value())
    }

    pub fn alps(&self) -> Option<&ALPS> {
        let extension = self.extensions.iter().find(|x| x.extension_type() == &ExtensionType::ApplicationLayerProtocolNegotiation)?;
        extension.alps()
    }

    pub fn remove_h2_alpn(&mut self) {
        let extend = self.extensions.iter_mut().find(|x| x.extension_type() == &ExtensionType::ApplicationLayerProtocolNegotiation);
        if let Some(ext) = extend {
            ext.remove_h2_alpn();
        }
        let extend = self.extensions.iter_mut().find(|x| x.extension_type() == &ExtensionType::ApplicationSetting);
        if let Some(ext) = extend {
            ext.remove_h2_alpn();
        }
    }

    pub fn remove_tls13(&mut self) {
        let pos = self.extensions.iter().position(|x| x.extension_type() == &ExtensionType::PreSharedKey);
        if let Some(pos) = pos {
            self.extensions.remove(pos);
        }
        let extend = self.extensions.iter_mut().find(|x| x.extension_type() == &ExtensionType::SupportedVersions);
        if let Some(ext) = extend {
            ext.remove_tls13()
        }
    }

    pub fn add_h2_alpn(&mut self) {
        let extend = self.extensions.iter_mut().find(|x| x.extension_type() == &ExtensionType::ApplicationLayerProtocolNegotiation);
        if let Some(ext) = extend {
            ext.add_h2_alpn();
        }
        let extend = self.extensions.iter_mut().find(|x| x.extension_type() == &ExtensionType::ApplicationSetting);
        if let Some(ext) = extend {
            ext.add_h2_alpn();
        }
    }

    pub fn cipher_suites(&self) -> &Vec<CipherSuite> {
        &self.cipher_suites
    }

    pub fn take_extensions(&mut self) -> Vec<Extension> {
        mem::take(&mut self.extensions)
    }
}

