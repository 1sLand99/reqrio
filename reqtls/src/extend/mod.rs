use super::bytes::Bytes;
use algorithm::SignatureAlgorithms;
use alps::ALPS;
use certificate::CompressionCertificate;
use client_hello::EncryptClientHello;
use formats::EcPointFormats;
use group::SupportedGroups;
use key_share::KeyShare;
use psk_key::PskKey;
use server_name::ServerName;
use status::StatusRequest;
use std::fmt::{Debug, Formatter};
use version::SupportVersions;

mod version;
pub mod formats;
mod server_name;
pub mod algorithm;
mod status;
pub mod group;
pub mod key_share;
pub mod alps;
mod client_hello;
mod certificate;
mod psk_key;
mod pre_share_key;

use crate::error::RlsResult;
use crate::extend::certificate::{CompressionKind, CompressionType};
use crate::Version;
pub use client_hello::Aead;
use crate::extend::pre_share_key::PreSharedKey;

#[derive(PartialEq)]
pub struct ExtensionType(u16);

impl ExtensionType {
    pub fn new(value: u16) -> ExtensionType { ExtensionType(value) }

    pub fn as_bytes(&self) -> [u8; 2] {
        self.0.to_be_bytes()
    }

    pub fn is_reserved(&self) -> bool {
        !ExtensionType::EXTENSIONS.contains(&self.0)
    }

    pub fn as_u16(&self) -> u16 { self.0 }

    pub fn default_value(&self) -> Option<ExtensionValue> {
        match *self {
            ExtensionType::ServerName => Some(ExtensionValue::ServerName(ServerName::new())),
            ExtensionType::StatusRequest => Some(ExtensionValue::StatusRequest(StatusRequest::new())),
            ExtensionType::SupportedGroup => Some(ExtensionValue::SupportedGroups(SupportedGroups::random())),
            ExtensionType::EcPointFormats => Some(ExtensionValue::EcPointFormats(EcPointFormats::random())),
            ExtensionType::SignatureAlgorithms => Some(ExtensionValue::SignatureAlgorithms(SignatureAlgorithms::random())),
            ExtensionType::ApplicationLayerProtocolNegotiation => Some(ExtensionValue::ApplicationLayerProtocolNegotiation(ALPS::new())),
            ExtensionType::SignedCertificateTimestamp => Some(ExtensionValue::SignedCertificateTimestamp),
            ExtensionType::EncryptTheMac => Some(ExtensionValue::EncryptTheMac),
            ExtensionType::ExtendMasterSecret => Some(ExtensionValue::MasterSecret),
            ExtensionType::SessionTicket => Some(ExtensionValue::SessionTicket),
            ExtensionType::CompressionCertificate => {
                let mut cp_cer = CompressionCertificate::new();
                cp_cer.push(CompressionType::new(CompressionKind::Null as u16));
                Some(ExtensionValue::CompressionCertificate(cp_cer))
            }
            ExtensionType::SupportedVersions => {
                let mut supported_versions = SupportVersions::new();
                supported_versions.push(Version::TLS_1_2);
                Some(ExtensionValue::SupportedVersions(supported_versions))
            }
            ExtensionType::PskKeyExchangeMode => Some(ExtensionValue::PskKeyExchangeMode(PskKey::new())),
            ExtensionType::KeyShare => Some(ExtensionValue::KeyShare(KeyShare::new())),
            ExtensionType::RenegotiationInfo => Some(ExtensionValue::RenegotiationInfo(RenegotiationInfo::new())),
            ExtensionType::EncryptedClientHello => Some(ExtensionValue::EncryptedClientHello(EncryptClientHello::new())),
            ExtensionType::ApplicationSetting => Some(ExtensionValue::ApplicationSetting(ALPS::new())),
            ExtensionType::PreSharedKey => Some(ExtensionValue::PreSharedKey(PreSharedKey::random())),
            _ => None
        }
    }
}

#[allow(non_upper_case_globals)]
impl ExtensionType {
    pub const ServerName: ExtensionType = ExtensionType(0x0);
    pub const StatusRequest: ExtensionType = ExtensionType(0x5);
    pub const SupportedGroup: ExtensionType = ExtensionType(0xa);
    pub const EcPointFormats: ExtensionType = ExtensionType(0xb);
    pub const SignatureAlgorithms: ExtensionType = ExtensionType(0xd);
    pub const ApplicationLayerProtocolNegotiation: ExtensionType = ExtensionType(0x10);
    pub const SignedCertificateTimestamp: ExtensionType = ExtensionType(0x12);
    pub const EncryptTheMac: ExtensionType = ExtensionType(0x16);
    pub const ExtendMasterSecret: ExtensionType = ExtensionType(0x17);
    pub const SessionTicket: ExtensionType = ExtensionType(0x23);
    pub const CompressionCertificate: ExtensionType = ExtensionType(0x1b);
    pub const SupportedVersions: ExtensionType = ExtensionType(0x2b);
    pub const PskKeyExchangeMode: ExtensionType = ExtensionType(0x2d);
    pub const KeyShare: ExtensionType = ExtensionType(0x33);
    pub const RenegotiationInfo: ExtensionType = ExtensionType(0xff01);
    pub const EncryptedClientHello: ExtensionType = ExtensionType(0xfe0d);
    pub const ApplicationSetting: ExtensionType = ExtensionType(0x44cd);
    pub const PreSharedKey: ExtensionType = ExtensionType(0x29);

    pub const EXTENSIONS: [u16; 18] = [0x0, 0x5, 0xa, 0xb, 0xd, 0x10, 0x12, 0x16, 0x17, 0x23, 0x1b, 0x2b, 0x2d, 0x33, 0xff01, 0xfe0d, 0x44cd, 0x29];

    pub fn spec(&self) -> &'static str {
        match self.0 {
            0x0 => "ServerName",
            0x5 => "StatusRequest",
            0xa => "SupportedGroup",
            0xb => "EcPointFormats",
            0xd => "SignatureAlgorithms",
            0x10 => "ApplicationLayerProtocolNegotiation",
            0x12 => "SignedCertificateTimestamp",
            0x16 => "EncryptTheMac",
            0x17 => "ExtendMasterSecret",
            0x23 => "SessionTicket",
            0x1b => "CompressionCertificate",
            0x2b => "SupportedVersions",
            0x2d => "PskKeyExchangeMode",
            0x33 => "KeyShare",
            0xff01 => "RenegotiationInfo",
            0xfe0d => "EncryptedClientHello",
            0x44cd => "ApplicationSetting",
            0x29 => "PreSharedKey",
            _ => "Reserved"
        }
    }
}

impl Debug for ExtensionType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}({})", self.spec(), self.0)
    }
}


#[derive(Debug)]
pub struct RenegotiationInfo {
    len: u8,
}

impl RenegotiationInfo {
    pub fn new() -> RenegotiationInfo {
        RenegotiationInfo { len: 0 }
    }
    pub fn from_bytes(byte: &[u8]) -> RenegotiationInfo {
        RenegotiationInfo {
            len: byte[0]
        }
    }

    pub fn as_u8(&self) -> u8 {
        self.len
    }
}

#[derive(Debug)]
pub enum ExtensionValue {
    PskKeyExchangeMode(PskKey),
    KeyShare(KeyShare),
    SupportedGroups(SupportedGroups),
    StatusRequest(StatusRequest),
    SignatureAlgorithms(SignatureAlgorithms),
    ServerName(ServerName),
    EcPointFormats(EcPointFormats),
    SupportedVersions(SupportVersions),
    RenegotiationInfo(RenegotiationInfo),
    ApplicationSetting(ALPS),
    EncryptedClientHello(EncryptClientHello),
    CompressionCertificate(CompressionCertificate),
    ApplicationLayerProtocolNegotiation(ALPS),
    SessionTicket,
    EncryptTheMac,
    MasterSecret,
    SignedCertificateTimestamp,
    PreSharedKey(PreSharedKey),
    Unknown(Bytes),
}

impl ExtensionValue {
    pub fn from_bytes(t: &ExtensionType, bytes: &[u8]) -> RlsResult<Self> {
        match *t{
            ExtensionType::ServerName => Ok(ExtensionValue::ServerName(ServerName::from_bytes(bytes)?)),
            ExtensionType::StatusRequest => Ok(ExtensionValue::StatusRequest(StatusRequest::from_bytes(bytes)?)),
            ExtensionType::SupportedGroup => Ok(ExtensionValue::SupportedGroups(SupportedGroups::from_bytes(bytes)?)),
            ExtensionType::EcPointFormats => Ok(ExtensionValue::EcPointFormats(EcPointFormats::from_bytes(bytes)?)),
            ExtensionType::SignatureAlgorithms => Ok(ExtensionValue::SignatureAlgorithms(SignatureAlgorithms::from_bytes(bytes)?)),
            ExtensionType::EncryptTheMac => Ok(ExtensionValue::EncryptTheMac),
            ExtensionType::ExtendMasterSecret => Ok(ExtensionValue::MasterSecret),
            ExtensionType::SessionTicket => Ok(ExtensionValue::SessionTicket),
            ExtensionType::RenegotiationInfo => Ok(ExtensionValue::RenegotiationInfo(RenegotiationInfo::from_bytes(bytes))),
            ExtensionType::SupportedVersions => Ok(ExtensionValue::SupportedVersions(SupportVersions::from_bytes(bytes))),
            ExtensionType::PskKeyExchangeMode => Ok(ExtensionValue::PskKeyExchangeMode(PskKey::from_bytes(bytes)?)),
            ExtensionType::CompressionCertificate => Ok(ExtensionValue::CompressionCertificate(CompressionCertificate::from_bytes(bytes)?)),
            ExtensionType::EncryptedClientHello => Ok(ExtensionValue::EncryptedClientHello(EncryptClientHello::from_bytes(bytes)?)),
            ExtensionType::SignedCertificateTimestamp => Ok(ExtensionValue::SignedCertificateTimestamp),
            ExtensionType::ApplicationSetting => Ok(ExtensionValue::ApplicationSetting(ALPS::from_bytes(bytes)?)),
            ExtensionType::KeyShare => Ok(ExtensionValue::KeyShare(KeyShare::from_bytes(bytes))),
            ExtensionType::ApplicationLayerProtocolNegotiation => Ok(ExtensionValue::ApplicationLayerProtocolNegotiation(ALPS::from_bytes(bytes)?)),
            ExtensionType::PreSharedKey => Ok(ExtensionValue::PreSharedKey(PreSharedKey::from_bytes(bytes)?)),
            _ => Ok(ExtensionValue::Unknown(Bytes::new(bytes.to_vec())))
        }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        match self {
            ExtensionValue::PskKeyExchangeMode(v) => v.as_bytes(),
            ExtensionValue::KeyShare(v) => v.as_bytes(),
            ExtensionValue::SupportedGroups(v) => v.as_bytes(),
            ExtensionValue::StatusRequest(v) => v.as_bytes(),
            ExtensionValue::SignatureAlgorithms(v) => v.as_bytes(),
            ExtensionValue::ServerName(v) => v.as_bytes(),
            ExtensionValue::EcPointFormats(v) => v.as_bytes(),
            ExtensionValue::SupportedVersions(v) => v.as_bytes(),
            ExtensionValue::RenegotiationInfo(v) => vec![v.as_u8()],
            ExtensionValue::SessionTicket => vec![],
            ExtensionValue::EncryptTheMac => vec![],
            ExtensionValue::MasterSecret => vec![],
            ExtensionValue::CompressionCertificate(v) => v.as_bytes(),
            ExtensionValue::EncryptedClientHello(v) => v.as_bytes(),
            ExtensionValue::ApplicationSetting(v) => v.as_bytes(),
            ExtensionValue::ApplicationLayerProtocolNegotiation(v) => v.as_bytes(),
            ExtensionValue::Unknown(v) => v.as_bytes(),
            ExtensionValue::SignedCertificateTimestamp => vec![],
            ExtensionValue::PreSharedKey(v) => v.as_bytes()
        }
    }
}

#[derive(Debug)]
pub struct Extension {
    type_: ExtensionType,
    len: u16,
    value: ExtensionValue,
}

impl Default for Extension {
    fn default() -> Self {
        Extension {
            type_: ExtensionType(0),
            len: 0,
            value: ExtensionValue::Unknown(Bytes::none()),
        }
    }
}

impl Extension {
    pub fn from_type(t: ExtensionType) -> Extension {
        let mut res = Extension::default();
        if let Some(value) = t.default_value() {
            res.value = value;
        }
        res.type_ = t;
        res
    }

    pub fn from_bytes(bytes: &[u8]) -> RlsResult<Vec<Extension>> {
        let mut res = vec![];
        let mut index = 0;
        while index < bytes.len() {
            let tv = u16::from_be_bytes([bytes[index], bytes[index + 1]]);
            let mut v = Extension::default();
            v.type_ = ExtensionType(tv);
            v.len = u16::from_be_bytes([bytes[index + 2], bytes[index + 3]]);
            v.value = ExtensionValue::from_bytes(&v.type_, &bytes[index + 4..index + 4 + v.len as usize])?;
            index += 4 + v.len as usize;
            res.push(v);
        }
        Ok(res)
    }

    pub fn extension_type(&self) -> &ExtensionType { &self.type_ }

    pub fn supported_groups(&self) -> Option<&SupportedGroups> {
        match &self.value {
            ExtensionValue::SupportedGroups(v) => Some(v),
            _ => None
        }
    }

    pub fn signature_algorithms(&self) -> Option<&SignatureAlgorithms> {
        match &self.value {
            ExtensionValue::SignatureAlgorithms(v) => Some(v),
            _ => None
        }
    }

    pub fn signature_algorithms_mut(&mut self) -> Option<&mut SignatureAlgorithms> {
        match &mut self.value {
            ExtensionValue::SignatureAlgorithms(v) => Some(v),
            _ => None
        }
    }

    pub fn supported_versions(&self) -> Option<&SupportVersions> {
        match &self.value {
            ExtensionValue::SupportedVersions(v) => Some(v),
            _ => None
        }
    }

    pub fn supported_versions_mut(&mut self) -> Option<&mut SupportVersions> {
        match &mut self.value {
            ExtensionValue::SupportedVersions(v) => Some(v),
            _ => None
        }
    }

    pub fn supported_groups_mut(&mut self) -> Option<&mut SupportedGroups> {
        match self.value {
            ExtensionValue::SupportedGroups(ref mut v) => Some(v),
            _ => None
        }
    }

    pub fn ex_point_formats(&self) -> Option<&EcPointFormats> {
        match &self.value {
            ExtensionValue::EcPointFormats(v) => Some(v),
            _ => None
        }
    }

    pub fn ex_point_formats_mut(&mut self) -> Option<&mut EcPointFormats> {
        match self.value {
            ExtensionValue::EcPointFormats(ref mut v) => Some(v),
            _ => None
        }
    }

    // pub fn application_layer_protocol_negotiation(&self) -> Option<&ALPS> {
    //     match &self.value {
    //         ExtensionValue::ApplicationLayerProtocolNegotiation(v) => Some(v),
    //         _ => None
    //     }
    // }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut res = self.type_.as_bytes().to_vec();
        let vbs = self.value.as_bytes();
        res.extend((vbs.len() as u16).to_be_bytes());
        res.extend(vbs);
        res
    }

    pub fn set_server_name(&mut self, value: &str) {
        if let ExtensionValue::ServerName(ref mut v) = self.value { v.set_value(value) }
    }

    pub fn server_name(&self) -> Option<&ServerName> {
        match self.value {
            ExtensionValue::ServerName(ref v) => Some(v),
            _ => None
        }
    }

    pub fn alps(&self) -> Option<&ALPS> {
        match self.value {
            ExtensionValue::ApplicationLayerProtocolNegotiation(ref v) => Some(v),
            _ => None
        }
    }

    pub fn alps_mut(&mut self) -> Option<&mut ALPS> {
        match self.value {
            ExtensionValue::ApplicationLayerProtocolNegotiation(ref mut v) => Some(v),
            _ => None
        }
    }

    pub fn remove_tls13(&mut self) {
        if let ExtensionValue::SupportedVersions(ref mut v) = self.value { v.remove_tls13() }
    }

    pub fn remove_h2_alpn(&mut self) {
        match self.value {
            ExtensionValue::ApplicationSetting(ref mut v) => v.remove_h2_alpn(),
            ExtensionValue::ApplicationLayerProtocolNegotiation(ref mut v) => v.remove_h2_alpn(),
            _ => {}
        }
    }

    pub fn add_h2_alpn(&mut self) {
        match self.value {
            ExtensionValue::ApplicationSetting(ref mut v) => v.add_h2_alpn(),
            ExtensionValue::ApplicationLayerProtocolNegotiation(ref mut v) => v.add_h2_alpn(),
            _ => {}
        }
    }
}