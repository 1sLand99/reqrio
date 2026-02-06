use std::mem;
use super::super::bytes::Bytes;
use super::super::cipher::suite::CipherSuite;
use super::super::extend::Extension;
use super::super::version::Version;
use super::HandshakeType;
use crate::boring::hash;
use crate::cipher::suite::CipherSuiteKind;
use crate::error::RlsResult;
use crate::extend::alps::ALPS;
use crate::extend::ExtensionType;
use crate::rand;


#[derive(Debug)]
pub struct ClientHello {
    handshake_type: HandshakeType,
    len: u32,
    version: Version,
    random: Bytes,
    session_id_len: u8,
    session_id: Bytes,
    cipher_suites_len: u16,
    cipher_suites: Vec<CipherSuite>,
    compress_method_len: u8,
    compress_method: Bytes,
    extend_len: u16,
    extensions: Vec<Extension>,
}

impl ClientHello {
    pub fn new() -> ClientHello {
        ClientHello {
            handshake_type: HandshakeType::ClientHello,
            len: 0,
            version: Version::new(0),
            random: Bytes::none(),
            session_id_len: 0,
            session_id: Bytes::none(),
            cipher_suites_len: 0,
            cipher_suites: vec![],
            compress_method_len: 0,
            compress_method: Bytes::none(),
            extend_len: 0,
            extensions: vec![],
        }
    }

    pub fn random() -> ClientHello {
        let mut res = ClientHello::new();
        res.random = Bytes::new(vec![0; 32]);
        res.version = Version::TLS_1_0;
        res.cipher_suites = vec![
            CipherSuite::new(CipherSuiteKind::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 as u16),
            CipherSuite::new(CipherSuiteKind::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 as u16),
            CipherSuite::new(CipherSuiteKind::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 as u16),
        ];
        let suite_all = CipherSuiteKind::all();
        // suite_all.remove(CipherSuiteKind::TLS_RSA_WITH_AES_128_CBC_SHA)
        while res.cipher_suites.len() < 12 {
            let index = rand::random::<usize>() % suite_all.len();
            let suite = CipherSuite::new(suite_all[index].clone() as u16);
            if res.cipher_suites.contains(&suite) { continue; }
            res.cipher_suites.push(suite);
        }
        res.compress_method = Bytes::new(vec![0]);
        res.extensions = vec![
            Extension::from_type(ExtensionType::SignatureAlgorithms),
            Extension::from_type(ExtensionType::SupportedGroup),
            Extension::from_type(ExtensionType::CompressionCertificate),
            Extension::from_type(ExtensionType::SupportedVersions),
            Extension::from_type(ExtensionType::ApplicationLayerProtocolNegotiation),
            Extension::from_type(ExtensionType::ServerName),
            Extension::from_type(ExtensionType::EcPointFormats),
        ];
        // let ext_all = ExtensionKind::all();
        // while res.extensions.len() < 9 {
        //     let index = rand::random::<usize>() % ext_all.len();
        //     let ext = ExtensionType::new(ext_all[index].clone() as u16);
        //     if res.extensions.iter().find(|x| x.extension_type().as_u16() == ext.as_u16()).is_some() { continue; }
        //     res.extensions.push(Extension::from_type(ext))
        // }
        res
    }

    pub fn from_bytes(ht: HandshakeType, bytes: &[u8]) -> RlsResult<ClientHello> {
        let mut res = ClientHello::new();
        res.handshake_type = ht;
        res.len = u32::from_be_bytes([0, bytes[1], bytes[2], bytes[3]]);
        res.version = Version::new(u16::from_be_bytes([bytes[4], bytes[5]]));
        res.random = Bytes::new(bytes[6..38].to_vec());
        res.session_id_len = bytes[38];
        let index = 39 + res.session_id_len as usize;
        if index > bytes.len() { println!("{:x?}", bytes); }
        res.session_id = Bytes::new(bytes[39..index].to_vec());
        res.cipher_suites_len = u16::from_be_bytes([bytes[index], bytes[index + 1]]);
        res.cipher_suites = CipherSuite::from_bytes(&bytes[index + 2..index + 2 + res.cipher_suites_len as usize])?;
        let index = index + res.cipher_suites_len as usize + 2;
        res.compress_method_len = bytes[index];
        res.compress_method = Bytes::new(bytes[index + 1..index + 1 + res.compress_method_len as usize].to_vec());
        let index = index + res.compress_method_len as usize + 1;
        res.extend_len = u16::from_be_bytes([bytes[index], bytes[index + 1]].try_into()?);
        res.extensions = Extension::from_bytes(&bytes[index + 2..index + 2 + res.extend_len as usize], false)?;
        // println!("{}", res.ja3());
        // println!("{}", res.ja4());
        Ok(res)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut res = vec![self.handshake_type.as_u8(), 0, 0, 0];
        // res.extend_from_slice(&(self.len as u32).to_be_bytes()[1..]);
        res.extend(self.version.as_bytes());
        res.extend(self.random.as_bytes());
        res.push(self.session_id.len() as u8);
        res.extend(self.session_id.as_bytes());
        let mut cbs = vec![];
        for cipher_suite in &self.cipher_suites {
            cbs.extend(cipher_suite.as_bytes());
        }

        res.extend((cbs.len() as u16).to_be_bytes());
        res.extend(cbs);
        res.push(self.compress_method.len() as u8);
        res.extend(self.compress_method.as_bytes());
        let mut ebs = vec![];

        for extension in &self.extensions {
            ebs.extend(extension.as_bytes(false));
        }
        res.extend((ebs.len() as u16).to_be_bytes());
        res.extend(ebs);
        let len = (res.len() - 4) as u32;
        res[1..4].copy_from_slice(len.to_be_bytes()[1..].as_ref());
        res
    }

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
            formats.formats().iter().map(|x| x.as_u8().to_string()).collect::<Vec<_>>()
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
        let sign_algo = ext.map(|x| Some(x.signature_algorithms()?.hashes().iter().map(|x| *x as u16).collect::<Vec<_>>()));
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

    pub fn set_random(&mut self, random: [u8; 32]) {
        self.random = Bytes::new(random.to_vec());
    }

    pub fn take_random(&mut self) -> Vec<u8> {
        mem::take(&mut self.random).to_bytes()
    }

    pub fn set_session_id(&mut self, session_id: [u8; 32]) {
        self.session_id = Bytes::new(session_id.to_vec());
    }

    pub fn set_server_name(&mut self, server_name: &str) {
        let extend = self.extensions.iter_mut().find(|x| x.extension_type() == &ExtensionType::ServerName);
        if let Some(ext) = extend {
            ext.set_server_name(server_name);
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
        // let pos = self.extensions.iter().position(|x| x.extension_type() == &ExtensionType::KeyShare);
        // if let Some(pos) = pos {
        //     self.extensions.remove(pos);
        // }
        // let pos = self.extensions.iter().position(|x| x.extension_type() == &ExtensionType::PskKeyExchangeMode);
        // if let Some(pos) = pos {
        //     self.extensions.remove(pos);
        // }
        // let pos = self.extensions.iter().position(|x| x.extension_type() == &ExtensionType::SessionTicket);
        // if let Some(pos) = pos {
        //     self.extensions.remove(pos);
        // }
        // let pos = self.extensions.iter().position(|x| x.extension_type() == &ExtensionType::SignedCertificateTimestamp);
        // if let Some(pos) = pos {
        //     self.extensions.remove(pos);
        // }
        // let pos = self.extensions.iter().position(|x| x.extension_type() == &ExtensionType::EcPointFormats);
        // if let Some(pos) = pos {
        //     self.extensions.remove(pos);
        // }
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

    pub fn len(&self) -> u32 {
        self.len
    }

    pub fn cipher_suites(&self) -> &Vec<CipherSuite> {
        &self.cipher_suites
    }

    pub fn take_extensions(&mut self) -> Vec<Extension> {
        mem::take(&mut self.extensions)
    }
}

