use crate::boring::BoringResExt;
use crate::buffer::Buf;
use crate::error::RlsResult;
use crate::extend::{ExtensionType, StatusRequest};
use crate::*;
#[cfg(debug_assertions)]
use std::fmt::Debug;
use std::os::raw::{c_int, c_void};
use std::ptr::null;

#[cfg_attr(debug_assertions, derive(Debug))]
pub enum Extension {
    KeyShare(Vec<KeyEntry>),
    StatusRequest(StatusRequest),
    ServerName(Vec<ServerName>),
    SupportedGroups(Vec<NamedCurve>),
    SupportedVersions(Vec<Version>),
    ApplicationLayerProtocolNegotiation(Vec<ALPN>),
    ApplicationSettings(Vec<ALPN>),
    ApplicationSettingOld(Vec<ALPN>),
    CompressionCertificate(Vec<CompressionMethod>),
    EcPointFormats(Vec<EcPointFormat>),
    PskKeyExchangeModes(Vec<PskMode>),
    SignatureAlgorithms(Vec<SignatureAlgorithm>),
    SessionTicket(Buf<'static>),
    EncryptedClientHello(Buf<'static>),
    RenegotiationInfo(Buf<'static>),
    Padding(usize),
    ExtendedMasterSecret,
    SignedCertificateTimestamp,
    EncryptTheMac,
    Reversed { typ: ExtensionType, value: Buf<'static> },
}

impl Extension {
    pub const RENEGOTIATION_INFO: Extension = Extension::RenegotiationInfo(Buf::Ref(&[0]));

    pub fn default_value(ty: ExtensionType) -> Option<Extension> {
        match ty {
            ExtensionType::ServerName => Some(Extension::ServerName(vec![ServerName::HOSTNAME])),
            ExtensionType::StatusRequest => Some(Extension::StatusRequest(StatusRequest::OCSP)),
            ExtensionType::SupportedGroup => Some(Extension::SupportedGroups(vec![
                NamedCurve::X25519,
                NamedCurve::SecP256r1,
                NamedCurve::SecP384r1,
                NamedCurve::SecP521r1,
            ])),
            ExtensionType::EcPointFormats => Some(Extension::EcPointFormats(vec![EcPointFormat::UNCOMPRESSED])),
            ExtensionType::SignatureAlgorithms => Some(Extension::SignatureAlgorithms(SignatureAlgorithms::random())),
            ExtensionType::ApplicationLayerProtocolNegotiation => Some(Extension::ApplicationLayerProtocolNegotiation(vec![ALPN::HTTP20, ALPN::HTTP11])),
            ExtensionType::SignedCertificateTimestamp => Some(Extension::SignedCertificateTimestamp),
            ExtensionType::EncryptTheMac => Some(Extension::EncryptTheMac),
            ExtensionType::ExtendMasterSecret => Some(Extension::ExtendedMasterSecret),
            ExtensionType::SessionTicket => Some(Extension::SessionTicket(Buf::Ref(&[]))),
            ExtensionType::CompressionCertificate => Some(Extension::CompressionCertificate(vec![CompressionMethod::NULL])),
            ExtensionType::SupportedVersions => Some(Extension::SupportedVersions(vec![
                Version::TLS_1_3,
                Version::TLS_1_2,
            ])),
            ExtensionType::PskKeyExchangeMode => Some(Extension::PskKeyExchangeModes(vec![PskMode::PSK_DHE_KE])),
            ExtensionType::KeyShare => Some(Extension::KeyShare(vec![])),
            ExtensionType::RenegotiationInfo => Some(Extension::RENEGOTIATION_INFO),
            // ExtensionType::EncryptedClientHello => Some(Extension::EncryptedClientHello(EncryptClientHello::new())),
            ExtensionType::ApplicationSetting => Some(Extension::ApplicationSettings(vec![ALPN::HTTP20, ALPN::HTTP11])),
            ExtensionType::ApplicationSettingOld => Some(Extension::ApplicationSettingOld(vec![ALPN::HTTP20, ALPN::HTTP11])),
            // ExtensionType::PreSharedKey => Some(Extension::PreSharedKey(extend::pre_share_key::PreSharedKey::random())),
            ExtensionType::Padding => Some(Extension::Padding(202)),
            _ => None
        }
    }

    fn build_extend(&self) -> Extend {
        match self {
            Extension::KeyShare(entries) => Extend::new(ExtensionType::KeyShare, entries.len() as u16, entries.as_slice()),
            Extension::StatusRequest(status_request) => Extend::new(ExtensionType::StatusRequest, 1, status_request),
            Extension::ServerName(server_name) => Extend::new_slice(ExtensionType::ServerName, server_name.as_slice()),
            Extension::SupportedGroups(groups) => Extend::new_slice(ExtensionType::SupportedGroup, groups.as_slice()),
            Extension::SupportedVersions(versions) => Extend::new_slice(ExtensionType::SupportedVersions, versions.as_slice()),
            Extension::ApplicationLayerProtocolNegotiation(alps) => Extend::new_slice(ExtensionType::ApplicationLayerProtocolNegotiation, alps.as_slice()),
            Extension::ApplicationSettings(alps) => Extend::new_slice(ExtensionType::ApplicationSetting, alps.as_slice()),
            Extension::ApplicationSettingOld(alps) => Extend::new_slice(ExtensionType::ApplicationSettingOld, alps.as_slice()),
            Extension::EcPointFormats(formats) => Extend::new_slice(ExtensionType::EcPointFormats, formats.as_slice()),
            Extension::CompressionCertificate(methods) => Extend::new_slice(ExtensionType::CompressionCertificate, methods.as_slice()),
            Extension::RenegotiationInfo(info) => Extend::new_slice(ExtensionType::RenegotiationInfo, info.as_ref()),
            Extension::SignedCertificateTimestamp => Extend::new_null(ExtensionType::SignedCertificateTimestamp),
            Extension::SignatureAlgorithms(algorithms) => Extend::new_slice(ExtensionType::SignatureAlgorithms, algorithms.as_slice()),
            Extension::PskKeyExchangeModes(modes) => Extend::new_slice(ExtensionType::PskKeyExchangeMode, modes.as_slice()),
            Extension::SessionTicket(ticket) => Extend::new_slice(ExtensionType::SessionTicket, ticket.as_ref()),
            Extension::EncryptedClientHello(encrypted_client_hello) => Extend::new_slice(ExtensionType::EncryptedClientHello, encrypted_client_hello.as_ref()),
            Extension::ExtendedMasterSecret => Extend::new_null(ExtensionType::ExtendMasterSecret),
            Extension::EncryptTheMac => Extend::new_null(ExtensionType::EncryptTheMac),
            Extension::Padding(size) => Extend { typ: ExtensionType::Padding, len: *size as u16, value: &StatusRequest::OCSP as *const StatusRequest as *const c_void },
            Extension::Reversed { typ, value } => Extend::new_slice(*typ, value.as_ref()),
        }
    }
}


#[repr(C)]
struct Extend {
    typ: ExtensionType,
    len: u16,
    value: *const c_void,
}

impl Extend {
    pub const fn new<T: ?Sized>(typ: ExtensionType, len: u16, value: &T) -> Extend {
        Extend {
            typ,
            len,
            value: value as *const T as *mut c_void,
        }
    }

    pub const fn new_null(typ: ExtensionType) -> Extend {
        Extend {
            typ,
            len: 0,
            value: null(),
        }
    }

    pub const fn new_slice<T>(typ: ExtensionType, slice: &[T]) -> Extend {
        Extend {
            typ,
            len: slice.len() as u16,
            value: slice.as_ptr() as *const c_void,
        }
    }
}

unsafe extern "C" {
    #[allow(improper_ctypes)]
    fn Record_build(config: *mut Config, typ: u8) -> c_int;
    #[allow(improper_ctypes)]
    fn Record_build_client_hello(config: *mut Config, record_version: Version, reader: *mut Reader) -> c_int;
    #[allow(improper_ctypes)]
    fn Record_build_custom(
        config: *mut Config,
        record_version: Version,
        suite_count: usize,
        suites: *const u16,
        message_version: Version,
        ext_count: usize,
        extensions: *const Extend,
    ) -> c_int;
}

#[cfg_attr(debug_assertions, derive(Debug))]
pub enum TlsFinger {
    Default,
    ClientHello {
        ///record layer version
        record_version: Version,
        ///client hello bytes
        bytes: Buf<'static>,
    },
    Custom {
        ///record layer version
        record_version: Version,
        ///handshake message version
        message_version: Version,
        ///cipher suites
        suites: Vec<CipherSuite>,
        ///extension
        extensions: Vec<Extension>,
    },
}

#[repr(C)]
struct Config {
    sni_len: u16,
    sni: *const u8,
    alpn: ALPN,
    version: Version,
    writer: *mut Writer,
    finger_type: c_int,
    conn: *mut Connection,
}

impl TlsFinger {
    pub const DEFAULT: &'static TlsFinger = &TlsFinger::Default;
    pub fn build_client_hello(&self, writer: &mut Writer, alpn: &ALPN, sni: &str, ver: Version, conn: &mut Connection) -> Result<(), &str> {
        let mut config = Config {
            sni_len: sni.len() as u16,
            sni: sni.as_ptr(),
            alpn: alpn.clone(),
            version: ver,
            writer,
            finger_type: 0,
            conn,
        };
        match self {
            TlsFinger::Default => unsafe { Record_build(&mut config, 1) }
            TlsFinger::ClientHello { bytes, record_version } => unsafe {
                Record_build_client_hello(&mut config, *record_version, &mut Reader::from_slice(bytes.as_ref()))
            }
            TlsFinger::Custom { suites, extensions, message_version, record_version } => {
                unsafe {
                    Record_build_custom(
                        &mut config,
                        *record_version,
                        suites.len(),
                        suites.iter().map(|x| x.value()).collect::<Vec<_>>().as_ptr(),
                        *message_version,
                        extensions.len(),
                        extensions.iter().map(|x| x.build_extend()).collect::<Vec<_>>().as_ptr(),
                    )
                }
            }
        }.ok("build client hello failed")
    }

    pub fn record_version(&self) -> Version {
        match self {
            TlsFinger::Default => Version::TLS_1_0,
            TlsFinger::ClientHello { record_version, .. } => *record_version,
            TlsFinger::Custom { record_version, .. } => *record_version,
        }
    }

    fn random_formats() -> Vec<EcPointFormat> {
        let mut ec_formats: Vec<EcPointFormat> = vec![];
        while ec_formats.len() < 3 {
            let format = EcPointFormat::ALL[rand::random::<usize>() % 3];
            if ec_formats.iter().any(|x| x == &format) { continue; }
            ec_formats.push(format);
        }
        ec_formats
    }

    fn random_algorithms() -> Vec<SignatureAlgorithm> {
        let mut algorithms: Vec<SignatureAlgorithm> = vec![
            SignatureAlgorithm::RSA_PSS_RSAE_SHA256,
            SignatureAlgorithm::ECDSA_SECP256R1_SHA256,
            SignatureAlgorithm::RSA_PKCS1_SHA256,
        ];
        while algorithms.len() < 16 {
            let alg = SignatureAlgorithm::ALL[rand::random::<usize>() % 23];
            if algorithms.iter().any(|x| x == alg) { continue; }
            algorithms.push(alg.into());
        }
        algorithms
    }

    pub fn random() -> TlsFinger {
        let mut suites: Vec<CipherSuite> = vec![
            CipherSuite::TLS_AES_128_GCM_SHA256,
            CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        ];
        while suites.len() < 16 {
            let suite = CipherSuite::ALL[rand::random::<usize>() % 31];
            if suites.contains(&suite) { continue; }
            suites.push(suite);
        }
        let mut groups: Vec<NamedCurve> = vec![NamedCurve::X25519, NamedCurve::SecP256r1];
        while groups.len() < 5 {
            let group = NamedCurve::ALL[rand::random::<usize>() % 11];
            if groups.contains(&group) { continue; }
            groups.push(group);
        }
        let mut versions: Vec<Version> = vec![Version::TLS_1_2];
        while versions.len() < 3 {
            let ver = Version::ALL[rand::random::<usize>() % 4];
            if versions.iter().any(|x| x == &ver) { continue; }
            versions.push(ver);
        }

        TlsFinger::Custom {
            record_version: Version::TLS_1_0,
            message_version: Version::TLS_1_2,
            suites,
            extensions: vec![
                Extension::SignatureAlgorithms(TlsFinger::random_algorithms()),
                Extension::SupportedGroups(groups.clone()),
                Extension::KeyShare(groups.into_iter().map(KeyEntry::new).collect()),
                Extension::CompressionCertificate(vec![CompressionMethod::NULL]),
                Extension::SupportedVersions(versions),
                Extension::ApplicationLayerProtocolNegotiation(vec![ALPN::HTTP20, ALPN::HTTP11]),
                Extension::ServerName(vec![ServerName::new_sni("")]),
                Extension::EcPointFormats(TlsFinger::random_formats()),
                Extension::RenegotiationInfo(Buf::Ref(&[0])),
                Extension::ExtendedMasterSecret,
                Extension::StatusRequest(StatusRequest::default()),
            ],
        }
    }

    pub fn from_ja3(ja3: impl AsRef<str>) -> RlsResult<TlsFinger> {
        let items = ja3.as_ref().split(",").collect::<Vec<_>>();
        let mut versions = vec![];
        let version = items.first().ok_or("version not found")?.parse::<u16>()?;
        for v in Version::ALL {
            if v < version { continue; }
            versions.insert(0, v);
        }
        let mut suites: Vec<CipherSuite> = vec![];
        for suite in items.get(1).ok_or("suites not found")?.split("-") {
            suites.push(suite.parse::<u16>()?.into());
        }
        let mut groups: Vec<NamedCurve> = vec![];
        for kid in items.get(3).ok_or("groups not found")?.split("-") {
            groups.push(NamedCurve::new(kid.parse()?));
        }
        let mut ec_formats: Vec<EcPointFormat> = vec![];
        for ft in items.get(4).ok_or("fts not found")?.split("-") {
            ec_formats.push(EcPointFormat::new(ft.parse()?));
        }
        let mut extensions = vec![];
        for ext in items.get(2).ok_or("exts not found")?.split("-") {
            let typ = ExtensionType::new(ext.parse::<u16>()?);
            extensions.push(match typ {
                ExtensionType::SupportedVersions => Extension::SupportedVersions(versions.clone()),
                ExtensionType::SupportedGroup => Extension::SupportedGroups(groups.clone()),
                ExtensionType::KeyShare => Extension::KeyShare(groups.clone().into_iter().map(KeyEntry::new).collect()),
                ExtensionType::EcPointFormats => Extension::EcPointFormats(ec_formats.clone()),
                ExtensionType::SignatureAlgorithms => Extension::SignatureAlgorithms(TlsFinger::random_algorithms()),
                ExtensionType::CompressionCertificate => Extension::CompressionCertificate(vec![CompressionMethod::NULL]),
                _ => Extension::default_value(typ).unwrap_or_else(|| Extension::Reversed { typ, value: Buf::Ref(&[]) })
            });
        }
        Ok(TlsFinger::Custom {
            record_version: Version::TLS_1_0,
            message_version: Version::TLS_1_2,
            suites,
            extensions,
        })
    }

    pub fn from_ja4(ja4: impl AsRef<str>) -> RlsResult<TlsFinger> {
        let items = ja4.as_ref().split("_").collect::<Vec<_>>();
        if items.len() != 4 { return Err("ja4 is error".into()); }
        let mut algorithms: Vec<SignatureAlgorithm> = vec![];
        for algo in items[3].split(",") {
            algorithms.push(SignatureAlgorithm::new(u16::from_str_radix(algo, 16)?));
        }

        let mut suites: Vec<CipherSuite> = vec![];
        for suite in items[1].split(",") {
            suites.push(u16::from_str_radix(suite, 16)?.into());
        }

        let versions = match &items[0][1..3] {
            "13" => vec![Version::TLS_1_3, Version::TLS_1_2, Version::TLS_1_1, Version::TLS_1_0],
            "12" => vec![Version::TLS_1_2, Version::TLS_1_1, Version::TLS_1_1],
            "11" => vec![Version::TLS_1_1, Version::TLS_1_0],
            "10" => vec![Version::TLS_1_0],
            _ => return Err("unknown tls version".into()),
        };
        let mut groups: Vec<NamedCurve> = vec![];
        while groups.len() < 5 {
            let group = NamedCurve::ALL[rand::random::<usize>() % 5];
            if groups.contains(&group) { continue; }
            groups.push(group);
        }

        let mut extensions = vec![];
        for ext in items.get(2).ok_or("exts not found")?.split(",") {
            let typ = ExtensionType::new(u16::from_str_radix(ext, 16)?);
            extensions.push(match typ {
                ExtensionType::SupportedVersions => Extension::SupportedVersions(versions.clone()),
                ExtensionType::SupportedGroup => Extension::SupportedGroups(groups.clone()),
                ExtensionType::KeyShare => Extension::KeyShare(groups.clone().into_iter().map(KeyEntry::new).collect()),
                ExtensionType::SignatureAlgorithms => Extension::SignatureAlgorithms(algorithms.clone()),
                ExtensionType::CompressionCertificate => Extension::CompressionCertificate(vec![CompressionMethod::BROTLI]),
                ExtensionType::EcPointFormats => Extension::EcPointFormats(TlsFinger::random_formats()),
                _ => Extension::default_value(typ).unwrap_or_else(|| Extension::Reversed { typ, value: Buf::Ref(&[]) })
            });
        }
        extensions.push(Extension::ServerName(vec![ServerName::HOSTNAME]));
        extensions.push(Extension::ApplicationLayerProtocolNegotiation(vec![ALPN::HTTP20, ALPN::HTTP11]));
        Ok(TlsFinger::Custom {
            record_version: Version::TLS_1_0,
            message_version: Version::TLS_1_2,
            suites,
            extensions,
        })
    }

    ///record hex prefix: 220303
    pub fn from_record_hex(record: impl AsRef<str>) -> RlsResult<TlsFinger> {
        let mut client_hello = hex::decode(record.as_ref())?;
        let ver = Version::new(u16::from_be_bytes([client_hello[1], client_hello[2]]));
        let len = u16::from_be_bytes([client_hello[3], client_hello[4]]) as usize + 5;
        let _ = client_hello.split_off(len);
        let client_hello = client_hello.split_off(5);
        Ok(TlsFinger::ClientHello { record_version: ver, bytes: Buf::Vec(client_hello) })
    }

    pub fn add_cipher_suite(&mut self, suite: CipherSuite) {
        if let TlsFinger::Custom { suites, .. } = self {
            suites.push(suite);
        }
    }

    pub fn add_extension(&mut self, value: Extension) {
        if let TlsFinger::Custom { extensions, .. } = self {
            extensions.push(value)
        }
    }

    pub fn find_mut(&mut self, typ: u16) -> Option<&mut Extension> {
        match self {
            TlsFinger::Default => None,
            TlsFinger::ClientHello { .. } => None,
            TlsFinger::Custom { extensions, .. } => None // extensions.iter_mut().find(|x| **x == typ)
        }
    }
}


#[cfg(test)]
mod tests {
    use crate::extend::ExtensionType;
    use crate::finger::Extension;
    use crate::*;

    #[test]
    fn test_build_client_hello() {
        let mut record = hex::decode("16030106b4010006b00303f9c1f4f02e973b7c0ad7d2dd63318d231cd95b400ba97583b0308aa569128d5c207391e6fb8385fdffe0451547e7728714d69ded3d08afd7b896115e1c1f7ac33500202a2a130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035010006472a2a0000000500050100000000002b0007060a0a030403030023000000170000fe0d00ba0000010001e9002003f4432d9d68a1633d044fef75411c0143075011d1b8f5a85f78c343d0edf11b0090462702887383eff94e911d28c1fbe8f4327bc28f6e1cb5a1eef835666fbea10dd8137a39b4d115f0307ff08e8716fc3b1eb358d71763758a947eb5aa152f728def3c5809ca720b0b48e7d9bc8cb3ec490da5bc9cb1abf56c0e173dd9cc50b36a512da940dc1a59f05804d37795bd7991495b19db7680aecfb881964949896c4d884d177a55377e3cfdb1d9e8fe0470be002d0002010144cd00050003026832001b00030200020010000e000c02683208687474702f312e31000d001200100403080404010503080505010806060100120000000b0002010000000010000e00000b636e2e62696e672e636f6dff01000100003304ef04edeaea00010011ec04c08e6b216767083516290a1242cea38a38b67f372413f55a915f3353f9b5b66088159ee500da352842fa8377708e3993227c989d5dab312a52a8f06340db44b796505af2267b71a0781fa990c79a057df7cd844ac095ca7d3284a759bccae1f9b132db3b6d93b8f7d81a9e2b09dae6c573d1c81aab35079561cb5c1387e2600b43b8f3f0cd53f73d2c847746642121290a316a56d439017764186da3287443346781120bd568813bbd5d342bdef62482e19d28d156d69cb9af04506a7095cef97eaeb571c8eb05536836a686459ad609451733856134b55994bd3973f73b48d187489f371e4d2384675842bc3196121cafd42c1ed08099b4425217677ee6391cdf1c1a32a4138ea546891ba4ab03c674794e031c5a9c4663b71917cfab879af163ce92012a7a8403932b1d187fbee177b444568517a10e814b1400ba5398bc04f899bdb45bac553795ac60467767bc37682738b435407c2f18c722f82132148846f65a8b627fd5a00baff7b97e419832b813285c6d04f806e9b0513ce3c9d04648412018f3eb19b2891542c4917880b435db57bc3239847bb31fe344f2576eabd3c1303c51abc04bb39b2629413c09541d6da213ca6539f64410f0a03c20bc08511825b4266017d66ce5165ee995925707a543327c9cdb490ed069c1704a7fb654ffc1af67d7cb970b048a500429e6c443380ed2a83026ca5dbd4b626b0a692ec6983e94b148a79931e4520c02934959ba9d18572fc18bf887a9e4d056c6584a79f7642f2b4fe2590b9ed0a6caba50b9258fe941890bdc634f077b8be2a67dc5a33737a49d58229a43849d9c95aed42bc2d0ca48fcaf38671daea424ac4c1f953a6c77c82c3392aee7243e399983c0bc14187355ef9b94111206fb02abcb6003f8c486d46a09ab2a4b0398c231e94c3eab4bc5668e70ea2b2588c851d92654a8cc37183edef6be7628c2169a7bdf367023045dff0980151993f5a0950587a3ff739bdf63724aa13edd535940d35f2e023e30d58549c952e65683559920ad906bf5cb4475a2ae9ba330f3d2c950b780ae0141e34b8b7ba3a71d7c020fd525fcdb08f010076307aabf25c99e4124cdc895d1959461792b79a1b004325107f699c36cad2819c8c3d2992f589fd82526a4ba828e9cc8e52b26a6460c9a7029f2da8a67d323f098257c67693b8929a360a23dc53a74e65687ca7dc5a96f09b25f50eb7876447e057b31505a167ffb8bb2117271ac84b11187ea73ba9b323102f296ead48b55f3877054bbbda23c1cd6cb6b6ba69224a484fca34da06e2179bda55c5be56c6e4dd971156496eab86bdb48b5d1d87f08201959d12193626a83a54f9428134395c0f9563d87c6417438c55ca25cbb925f07492b5ae34110822a74c827d8d79b4e1c95cd79b7edf5acc6f6b4dd033e99a68ec9c22f004843c5b89e741cb05e4b62786521ea26a2bebc9eddc9cc14c2c854915b23d14e2a6386528c34683903415508c16c7877099d1a4ccab7ccc07f1aaeb76170c4d17936e8b8d1314dc5bcc00f2b22b64cc94b243abbeb7f89c24e745487ef184ed5a2925ea9737de96f3815945a54909a1b5e6f68c38363a3e72cba70fb2f0edbb141d81902d45000e27e3c34f6f1b1ac187252f220fb316dabc9f0852b3e1a03dd117fef87b9267d475c7e78d0759a1ba2faa96429875d78a0f94933aacea3552a128b1a87961524a26e001d0020bf27edb88eec8a7692084494366aef172563b8eaf33aeb9d8b871a22c60fa564000a000c000aeaea11ec001d00170018dada000100").unwrap();
        let finger = TlsFinger::ClientHello {
            record_version: Version::TLS_1_0,
            bytes: Buf::Vec(record.split_off(5)),
        };
        let mut writer = Writer::with_capacity(4096);
        let mut connection = Connection::new_client(TlsSession::default(), None, false);
        finger.build_client_hello(&mut writer, &ALPN::HTTP20, "www.baidu.com", Version::TLS_1_2, &mut connection).unwrap();
        assert!(RecordLayer::from_bytes(writer.filled(), KeyExchangeAlg::NULL, false).is_ok());
    }

    #[test]
    fn test_build_default() {
        let finger = TlsFinger::Default;
        let mut writer = Writer::with_capacity(4096);
        let mut connection = Connection::new_client(TlsSession::default(), None, false);
        finger.build_client_hello(&mut writer, &ALPN::HTTP11, "www.baidu.com", Version::TLS_1_3, &mut connection).unwrap();
        assert!(RecordLayer::from_bytes(writer.filled(), KeyExchangeAlg::NULL, false).is_ok());
        // println!("{:#?}", RecordLayer::from_bytes(writer.filled(), KeyExchangeAlg::NULL, false).unwrap());
    }

    #[test]
    fn test_record() {
        let finger = TlsFinger::Custom {
            record_version: Version::TLS_1_0,
            message_version: Version::TLS_1_2,
            suites: vec![
                CipherSuite::from(0x2a2a),
                CipherSuite::TLS_AES_128_GCM_SHA256,
                CipherSuite::TLS_AES_256_GCM_SHA384,
                CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384,
                CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
                CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA,
            ],
            extensions: vec![
                Extension::Reversed { typ: ExtensionType::new(0x2a2a), value: Buf::Ref(&[]) },
                Extension::StatusRequest(StatusRequest::OCSP),
                Extension::SupportedVersions(vec![
                    Version::new(0x0a0a),
                    Version::TLS_1_3,
                    Version::TLS_1_2
                ]),
                Extension::SessionTicket(Buf::Ref(&[])),
                Extension::ExtendedMasterSecret,
                Extension::EncryptedClientHello(Buf::Vec(hex::decode("0000010001e9002003f4432d9d68a1633d044fef75411c0143075011d1b8f5a85f78c343d0edf11b0090462702887383eff94e911d28c1fbe8f4327bc28f6e1cb5a1eef835666fbea10dd8137a39b4d115f0307ff08e8716fc3b1eb358d71763758a947eb5aa152f728def3c5809ca720b0b48e7d9bc8cb3ec490da5bc9cb1abf56c0e173dd9cc50b36a512da940dc1a59f05804d37795bd7991495b19db7680aecfb881964949896c4d884d177a55377e3cfdb1d9e8fe0470be").unwrap())),
                Extension::PskKeyExchangeModes(vec![PskMode::PSK_DHE_KE]),
                Extension::ApplicationSettings(vec![
                    ALPN::HTTP20
                ]),
                Extension::CompressionCertificate(vec![
                    CompressionMethod::BROTLI
                ]),
                Extension::ApplicationLayerProtocolNegotiation(vec![
                    ALPN::HTTP20,
                    ALPN::HTTP11
                ]),
                Extension::SignatureAlgorithms(vec![
                    SignatureAlgorithm::ECDSA_SECP256R1_SHA256,
                    SignatureAlgorithm::RSA_PSS_RSAE_SHA256,
                    SignatureAlgorithm::RSA_PKCS1_SHA256,
                    SignatureAlgorithm::ECDSA_SECP384R1_SHA384,
                    SignatureAlgorithm::RSA_PSS_RSAE_SHA384,
                    SignatureAlgorithm::RSA_PKCS1_SHA384,
                    SignatureAlgorithm::RSA_PSS_RSAE_SHA512,
                    SignatureAlgorithm::RSA_PKCS1_SHA512
                ]),
                Extension::SignedCertificateTimestamp,
                Extension::EcPointFormats(vec![
                    EcPointFormat::UNCOMPRESSED
                ]),
                Extension::ServerName(vec![ServerName::HOSTNAME]),
                Extension::RenegotiationInfo(Buf::Ref(&[0])),
                Extension::KeyShare(vec![
                    KeyEntry::new(NamedCurve::new(REVERSED[rand::random::<usize>() % 16])),
                    KeyEntry::X25519MLKEM768,
                    KeyEntry::X25519,
                ]),
                Extension::SupportedGroups(vec![
                    NamedCurve::X25519MLKEM768,
                    NamedCurve::X25519,
                    NamedCurve::SecP256r1,
                    NamedCurve::SecP384r1
                ]),
                Extension::Reversed { typ: ExtensionType::new(0xdada), value: Buf::Ref(&[0]) }
            ],
        };
        let mut writer = Writer::with_capacity(4096);
        let mut connection = Connection::new_client(TlsSession::default(), None, false);
        finger.build_client_hello(&mut writer, &ALPN::HTTP20, "www.baidu.com", Version::TLS_1_2, &mut connection).unwrap();
        println!("{} {:?}", writer.len(), writer.filled());
        println!("{:#?}", RecordLayer::from_bytes(writer.filled(), KeyExchangeAlg::NULL, false).unwrap());
    }
}