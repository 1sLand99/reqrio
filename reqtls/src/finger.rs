use crate::*;
use crate::buffer::Buf;
use crate::error::RlsResult;
use crate::extend::algorithm::SignatureAlgorithms;
use crate::extend::ExtensionValue;
use crate::extend::formats::EcPointFormats;
use crate::extend::group::SupportedGroups;

#[derive(Debug)]
pub enum TlsFinger {
    ClientHello(Bytes),
    Custom {
        ///cipher suites
        suites: Vec<CipherSuite>,
        ///supported groups
        groups: Vec<NamedCurve>,
        ///signature algorithm
        algorithms: Vec<SignatureAlgorithm>,
        ///supported versions
        versions: Vec<Version>,
        ///ec point format
        ec_formats: Vec<EcPointFormat>,
        ///certificate compression
        compress_methods: Vec<CompressionMethod>,
        ///extension
        extensions: Vec<ExtensionType>,

    },
}

impl TlsFinger {
    pub fn build_client_hello(&self) -> Result<ClientHello<'_>, RlsError> {
        match self {
            TlsFinger::ClientHello(client_hello) => {
                let mut reader = Reader::from_slice(&client_hello.as_ref()[5..]);
                reader.read_u8()?;
                ClientHello::from_bytes(&mut reader)
            }
            TlsFinger::Custom {
                suites,
                groups,
                algorithms,
                versions,
                ec_formats,
                extensions,
                ..
            } => {
                let mut client_hello = ClientHello::default();
                client_hello.set_cipher_suites(suites.clone());
                for extension in extensions {
                    let extend = match *extension {
                        ExtensionType::SupportedGroup => {
                            let mut support_group = SupportedGroups::new();
                            for group in groups {
                                support_group.add_group(*group);
                            }
                            Extension::new(extension.clone(), ExtensionValue::SupportedGroups(support_group))
                        }
                        ExtensionType::SignatureAlgorithms => {
                            let mut sign_alg = SignatureAlgorithms::new();
                            for algorithm in algorithms {
                                sign_alg.push_hash(algorithm.clone());
                            }
                            Extension::new(extension.clone(), ExtensionValue::SignatureAlgorithms(sign_alg))
                        }
                        ExtensionType::SupportedVersions => {
                            let mut support_versions = SupportVersions::default();
                            for version in versions {
                                support_versions.push(*version);
                            }
                            Extension::new(extension.clone(), ExtensionValue::SupportedVersions(support_versions))
                        }
                        ExtensionType::EcPointFormats => {
                            let mut ec_point_formats = EcPointFormats::new();
                            for ec_format in ec_formats {
                                ec_point_formats.add_format(*ec_format);
                            }
                            Extension::new(extension.clone(), ExtensionValue::EcPointFormats(ec_point_formats))
                        }
                        ExtensionType::KeyShare => {
                            let mut key_share = KeyShare::default();
                            for group in groups {
                                if group != NamedCurve::X25519 && group != NamedCurve::Secp256r1 { continue; }
                                key_share.add_entry(*group, Buf::Ref(&[]))
                            }
                            Extension::new(extension.clone(), ExtensionValue::KeyShare(key_share))
                        }
                        _ => Extension::from_type(extension.clone()),
                    };
                    client_hello.add_extension(extend);
                }
                Ok(client_hello)
            }
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
            SignatureAlgorithm::RSA_PSS_RSAE_SHA256.into(),
            SignatureAlgorithm::ECDSA_SECP256R1_SHA256.into(),
            SignatureAlgorithm::RSA_PKCS1_SHA256.into(),
        ];
        while algorithms.len() < 16 {
            let alg = SignatureAlgorithm::ALL[rand::random::<usize>() % 23];
            if algorithms.iter().any(|x| x == alg) { continue; }
            algorithms.push(alg.into());
        }
        algorithms
    }

    pub fn random() -> RlsResult<TlsFinger> {
        let mut suites: Vec<CipherSuite> = vec![
            CipherSuite::TLS_AES_128_GCM_SHA256.into(),
            CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA.into(),
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.into(),
        ];
        while suites.len() < 16 {
            let suite = CipherSuite::ALL[rand::random::<usize>() % 31];
            if suites.iter().any(|x| x == suite) { continue; }
            suites.push(suite.into());
        }
        let mut groups: Vec<NamedCurve> = vec![NamedCurve::X25519.into(), NamedCurve::Secp256r1.into()];
        while groups.len() < 5 {
            let group = NamedCurve::ALL[rand::random::<usize>() % 11];
            if groups.iter().any(|x| x == group) { continue; }
            groups.push(group.into());
        }
        let mut versions: Vec<Version> = vec![Version::TLS_1_2];
        while versions.len() < 3 {
            let ver = Version::ALL[rand::random::<usize>() % 4];
            if versions.iter().any(|x| x == &ver) { continue; }
            versions.push(ver);
        }

        Ok(TlsFinger::Custom {
            suites,
            groups,
            algorithms: TlsFinger::random_algorithms(),
            versions,
            ec_formats: TlsFinger::random_formats(),
            compress_methods: vec![CompressionMethod::NULL],
            extensions: vec![
                ExtensionType::SignatureAlgorithms,
                ExtensionType::SupportedGroup,
                ExtensionType::CompressionCertificate,
                ExtensionType::SupportedVersions,
                ExtensionType::ApplicationLayerProtocolNegotiation,
                ExtensionType::ServerName,
                ExtensionType::EcPointFormats,
                ExtensionType::RenegotiationInfo,
                ExtensionType::ExtendMasterSecret,
                ExtensionType::StatusRequest,
                ExtensionType::KeyShare
            ],
        })
    }

    pub fn from_ja3(ja3: impl AsRef<str>) -> RlsResult<TlsFinger> {
        let mut items = ja3.as_ref().split(",");
        let mut versions = vec![];
        let version = items.next().ok_or("version not found")?.parse::<u16>()?;
        for v in Version::ALL {
            if v > version { continue; }
            versions.push(v);
        }
        let mut suites: Vec<CipherSuite> = vec![];
        for suite in items.next().ok_or("suites not found")?.split("-") {
            suites.push(suite.parse::<u16>()?.into());
        }
        let mut extensions = vec![];
        for ext in items.next().ok_or("exts not found")?.split("-") {
            extensions.push(ExtensionType::new(ext.parse()?));
        }
        let mut groups: Vec<NamedCurve> = vec![];
        for kid in items.next().ok_or("groups not found")?.split("-") {
            groups.push(NamedCurve::new(kid.parse()?));
        }
        let mut ec_formats: Vec<EcPointFormat> = vec![];
        for ft in items.next().ok_or("fts not found")?.split("-") {
            ec_formats.push(EcPointFormat::new(ft.parse()?));
        }
        Ok(TlsFinger::Custom {
            versions,
            suites,
            extensions,
            groups,
            ec_formats,
            algorithms: TlsFinger::random_algorithms(),
            compress_methods: vec![CompressionMethod::NULL],
        })
    }

    pub fn from_ja4(ja4: impl AsRef<str>) -> RlsResult<TlsFinger> {
        let items = ja4.as_ref().split("_").collect::<Vec<_>>();
        if items.len() != 4 { return Err("ja4 is error".into()); }
        let mut algorithms: Vec<SignatureAlgorithm> = vec![];
        for algo in items[3].split(",") {
            algorithms.push(SignatureAlgorithm::new(u16::from_str_radix(algo, 16)?));
        }

        let mut extensions = vec![];
        for ext in items[2].split(",") {
            extensions.push(ExtensionType::new(u16::from_str_radix(ext, 16)?));
        }
        extensions.push(ExtensionType::ServerName);
        extensions.push(ExtensionType::ApplicationLayerProtocolNegotiation);
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
            if groups.iter().any(|x| x == group) { continue; }
            groups.push(group.into());
        }
        Ok(TlsFinger::Custom {
            suites,
            versions,
            extensions,
            algorithms,
            groups,
            ec_formats: TlsFinger::random_formats(),
            compress_methods: vec![CompressionMethod::NULL],
        })
    }
}