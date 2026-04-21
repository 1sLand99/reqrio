use super::super::extend::Extension;
use super::super::suite::CipherSuite;
use super::super::version::Version;
use super::HandshakeType;
use crate::boring::hash;
use crate::buffer::Buf;
use crate::error::RlsResult;
use crate::extend::alps::ALPS;
use crate::extend::{ExtensionType, ExtensionValue, ServerName};
use crate::{u24, BufferError, KeyShare, ReadExt, Reader, WriteExt};
use std::mem;

#[derive(Debug)]
pub struct ClientHello<'a> {
    handshake_type: HandshakeType,
    len: u24,
    version: Version,
    random: Buf<'a>,
    session_id_len: u8,
    session_id: Buf<'a>,
    cipher_suites_len: u16,
    cipher_suites: Vec<CipherSuite>,
    compress_method_len: u8,
    compress_method: Buf<'a>,
    extend_len: u16,
    extensions: Vec<Extension<'a>>,
}

impl<'a> Default for ClientHello<'a> {
    fn default() -> Self {
        ClientHello {
            handshake_type: HandshakeType::ClientHello,
            len: 0,
            version: Version::TLS_1_2,
            random: Buf::Ref(&[]),
            session_id_len: 0,
            session_id: Buf::Ref(&[]),
            cipher_suites_len: 0,
            cipher_suites: vec![],
            compress_method_len: 1,
            compress_method: Buf::Ref(&[0]),
            extend_len: 0,
            extensions: vec![],
        }
    }
}

impl<'a> ClientHello<'a> {
    pub fn from_bytes(reader: &mut Reader<'a>) -> RlsResult<ClientHello<'a>> {
        let mut res = ClientHello::default();
        res.handshake_type = HandshakeType::ClientHello;
        res.len = reader.read_24()?;
        res.version = Version::new(reader.read_u16()?);
        res.random = Buf::Ref(reader.read_slice(32)?);
        res.session_id_len = reader.read_u8()?;
        res.session_id = Buf::Ref(reader.read_slice(res.session_id_len as usize)?);
        res.cipher_suites_len = reader.read_u16()?;
        for _ in (0..res.cipher_suites_len).step_by(2) {
            res.cipher_suites.push(CipherSuite::new(reader.read_u16()?));
        }

        res.compress_method_len = reader.read_u8()?;
        res.compress_method = Buf::Ref(reader.read_slice(res.compress_method_len as usize)?);
        res.extend_len = reader.read_u16()?;
        res.extensions = Extension::from_reader(reader.read_reader(res.extend_len as usize)?, false)?;
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

    pub fn write_to<W: WriteExt>(self, writer: &mut W) -> Result<(), BufferError> {
        writer.write_u8(self.handshake_type as u8)?;
        writer.write_u24(self.len() as u24 - 4)?;
        writer.write_u16(self.version.into_inner())?;
        writer.write_slice(self.random.as_ref())?;
        writer.write_u8(self.session_id.len() as u8)?;
        writer.write_slice(self.session_id.as_ref())?;
        let len = self.cipher_suites.iter().map(|_| 2).sum::<usize>();
        writer.write_u16(len as u16)?;
        for cipher_suite in self.cipher_suites {
            writer.write_u16(cipher_suite.into_inner())?;
        }
        writer.write_u8(self.compress_method.len() as u8)?;
        writer.write_slice(self.compress_method.as_ref())?;
        let len = self.extensions.iter().map(|x| x.len(false)).sum::<usize>();
        writer.write_u16(len as u16)?;
        for extension in self.extensions {
            extension.write_to(writer, false)?;
        }
        Ok(())
    }

    pub fn client_random(&mut self) -> &Buf<'a> { &self.random }

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
            formats.formats().iter().map(|x| (*x).into_inner().to_string()).collect::<Vec<_>>()
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
            let vers = versions.iter().find(|x| x.is_reverse())?;
            Some(vers.as_ja4_str())
        }).unwrap_or(Some("00")).unwrap_or("00");
        let mut suite = self.cipher_suites.iter().filter_map(|x| if x.is_reserved() {
            None
        } else {
            Some(x.as_u16())
        }).collect::<Vec<_>>();
        suite.sort();
        let mut exts = self.extensions.iter().filter_map(|x| if x.extension_type().is_reserved() || x.alps().is_some() || x.server_name().is_some() {
            None
        } else {
            Some(x.extension_type().as_u16())
        }).collect::<Vec<_>>();
        exts.sort();
        let ext = self.extensions.iter().find(|x| x.alps().is_some());
        let alps = ext.map(|ext| Some(ext.alps()?.values().first()?.value())).unwrap_or(Some("00")).unwrap_or("00");
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
        self.random = Buf::Ref(random);
    }

    pub fn set_session_id(&mut self, session_id: &'a [u8]) {
        self.session_id = Buf::Ref(session_id);
    }

    pub fn set_server_name(&mut self, server_name: &'a str) {
        let extend_type = ExtensionType::ServerName;
        let extend = self.extensions.iter_mut().find(|x| x.extension_type() == &extend_type);
        match extend {
            None => {
                let value = ExtensionValue::ServerName(ServerName::new().with_value(server_name));
                let ext = Extension::new(ExtensionType::ServerName, value);
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

    pub fn add_extension(&mut self, extension: Extension<'a>) {
        self.extensions.push(extension);
    }

    pub fn set_extension(&mut self, extension: Vec<Extension<'a>>) {
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

    pub fn add_h2_alpn(&mut self) {
        let extend = self.extensions.iter_mut().find(|x| x.extension_type() == &ExtensionType::ApplicationLayerProtocolNegotiation);
        if let Some(ext) = extend {
            ext.add_h2_alpn();
        } else {
            let mut alps = ALPS::new();
            alps.add_h2_alpn();
            self.extensions.push(Extension::new(ExtensionType::ApplicationLayerProtocolNegotiation, ExtensionValue::ApplicationLayerProtocolNegotiation(alps)));
        }
        let extend = self.extensions.iter_mut().find(|x| x.extension_type() == &ExtensionType::ApplicationSetting);
        if let Some(ext) = extend {
            ext.add_h2_alpn();
        } else {
            let mut alps = ALPS::new();
            alps.add_h2_alpn();
            self.extensions.push(Extension::new(ExtensionType::ApplicationSetting, ExtensionValue::ApplicationSetting(alps)));
        }
    }

    pub fn cipher_suites(&self) -> &Vec<CipherSuite> {
        &self.cipher_suites
    }

    pub fn take_extensions(&mut self) -> Vec<Extension<'_>> {
        mem::take(&mut self.extensions)
    }

    pub fn extensions_mut(&mut self) -> &mut [Extension<'a>] { &mut self.extensions }

    pub fn set_key_share(&mut self, key_share: KeyShare<'a>) {
        let extend = self.extensions.iter_mut().find(|x| x.extension_type() == &ExtensionType::KeyShare);
        match extend {
            None => self.extensions.push(Extension::new(ExtensionType::KeyShare, ExtensionValue::KeyShare(key_share))),
            Some(extend) => extend.set_key_share(key_share),
        }
    }

    pub fn key_share_mut(&mut self) -> Option<&mut KeyShare<'a>> {
        let extend = self.extensions.iter_mut().find(|x| x.extension_type() == &ExtensionType::KeyShare);
        extend.map(|x| x.key_share_mut()).unwrap_or(None)
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
}

