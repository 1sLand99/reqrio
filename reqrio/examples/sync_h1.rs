use std::fs;
use reqrio::*;

#[cfg(feature = "log")]
const LOGER: Logger = Logger {
    module: &[],
    debug_file: None,
    info_file: None,
    warn_file: None,
    error_file: None,
    out_file: None,
};

#[cfg(feature = "log")]
fn test_log() {
    set_logger(&LOGER).unwrap();
    set_max_level(LevelFilter::Debug);
}

const REVERSED: [u16; 15] = [0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xeaea, 0xfafa];

pub fn random_fingerprint(sni: &str) -> Result<Fingerprint, HlsError> {
    let group = REVERSED[rand::random::<usize>() % REVERSED.len()];
    let padding = 192 - (19 - sni.len() as i32);
    let tls = TlsFinger::Custom {
        suites: vec![
            CipherSuite::new(REVERSED[rand::random::<usize>() % REVERSED.len()]),
            CipherSuite::TLS_AES_128_GCM_SHA256.into(),
            CipherSuite::TLS_AES_256_GCM_SHA384.into(),
            CipherSuite::TLS_CHACHA20_POLY1305_SHA256.into(),
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.into(),
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.into(),
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.into(),
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.into(),
            CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256.into(),
            CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256.into(),
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.into(),
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA.into(),
            CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256.into(),
            CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384.into(),
            CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA.into(),
            CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA.into(),
        ],
        extensions: vec![
            Extension::new(ExtensionType::new(REVERSED[rand::random::<usize>() % REVERSED.len()]), ExtensionValue::Default),
            Extension::new_default(ExtensionType::ServerName),
            Extension::new_default(ExtensionType::ExtendMasterSecret),
            Extension::new_default(ExtensionType::RenegotiationInfo),
            Extension::new(ExtensionType::SupportedGroup, ExtensionValue::Curves(vec![
                NamedCurve::new(group),
                NamedCurve::X25519.into(),
                NamedCurve::SecP256r1.into(),
                NamedCurve::SecP384r1.into()
            ])),
            Extension::new(ExtensionType::EcPointFormats, ExtensionValue::EcPointFormats(vec![
                EcPointFormat::UNCOMPRESSED
            ])),
            Extension::new_default(ExtensionType::SessionTicket),
            Extension::new(ExtensionType::ApplicationLayerProtocolNegotiation, ExtensionValue::Alps(vec![
                ALPN::Http20,
                ALPN::Http11
            ])),
            Extension::new_default(ExtensionType::StatusRequest),
            Extension::new(ExtensionType::SignatureAlgorithms, ExtensionValue::Algorithms(vec![
                SignatureAlgorithm::ECDSA_SECP256R1_SHA256.into(),
                SignatureAlgorithm::RSA_PSS_RSAE_SHA256.into(),
                SignatureAlgorithm::RSA_PKCS1_SHA256.into(),
                SignatureAlgorithm::ECDSA_SECP384R1_SHA384.into(),
                SignatureAlgorithm::RSA_PSS_RSAE_SHA384.into(),
                SignatureAlgorithm::RSA_PKCS1_SHA384.into(),
                SignatureAlgorithm::RSA_PSS_RSAE_SHA512.into(),
                SignatureAlgorithm::RSA_PKCS1_SHA512.into()
            ])),
            Extension::new_default(ExtensionType::SignedCertificateTimestamp),
            Extension::new(ExtensionType::KeyShare, ExtensionValue::Curves(vec![
                NamedCurve::new(group),
                NamedCurve::X25519.into()
            ])),
            Extension::new(ExtensionType::PskKeyExchangeMode, ExtensionValue::PskMode(PskMode::PSK_DHE_KE)),
            Extension::new(ExtensionType::SupportedVersions, ExtensionValue::SupportedVersions(vec![
                Version::new(REVERSED[rand::random::<usize>() % REVERSED.len()]),
                Version::TLS_1_3,
                Version::TLS_1_2,
                Version::TLS_1_1,
                Version::TLS_1_0
            ])),
            Extension::new(ExtensionType::CompressionCertificate, ExtensionValue::CompressionMethods(vec![
                CompressionMethod::BROTLI
            ])),
            Extension::new(ExtensionType::ApplicationSettingOld, ExtensionValue::Alps(vec![
                ALPN::Http20
            ])),
            Extension::new(REVERSED[rand::random::<usize>() % REVERSED.len()], ExtensionValue::Bytes(Bytes::new(vec![0]))),
            Extension::new(ExtensionType::Padding, ExtensionValue::Padding(padding as usize))
        ],
    };
    Fingerprint::new_tls(tls, fs::read_to_string("TOKEN").unwrap_or("".to_string()))
}


fn main() {
    #[cfg(feature = "log")]
    test_log();
    let mut req = ScReq::new().with_alpn(ALPN::Http20).with_key_log("2.log");
    let headers = json::object! {
        "sec-ch-ua": "\"Microsoft Edge\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
        "sec-ch-ua_mobile": "?0",
        "sec-ch-ua_platform": "\"Linux\"",
        "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0"
    };
    let tls_hex = "16030106b2010006ae0303f0aed3d4d9fac0e8d4ff98981a90257765d203b4ce089c591e86d8e7ec8ab90a204803c2150a14429bfe6536328fe11cfd4034264fa2a3a443c5972eeeb93d427100206a6a130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035010006453a3a000000230000001b0003020002ff010001000000000e000c0000093338686d7a672e636e0005000501000000000017000044cd00050003026832fe0d00ba00000100010900208e3fc249e1ce71ff4aefb0970b38167b6b7de98537b874130ba4e284e15f1c4f00909540fc3a77fcc8f96d51ff9144785ccf114d3618d9a77b0e88f54d4dd1279083483e0ad83a4f25e55951194048709bf0842651d940c291569b9cfe1323d6fc2d31348ccaaa7b79271fc41af0975d94f7a826819154e05f6f90bdaa4e2b215894ccd36f748ded2bcae0a61aa101a7187588c2b45b51d076356d0e47728974d6d1cdd2b3ce4a8e5e8f70a79fb8f288c868000b00020100002d00020101000a000c000a3a3a11ec001d00170018001200000010000e000c02683208687474702f312e31003304ef04ed3a3a00010011ec04c05b20439ba8b50e3a5800981889512ab253cd2f1ba1488613fbd79f43813c08e34ed45330a62991a6b37890d54d2d0c089251b146acace84512c031c74ac6a2ac6345b6668629aa143357b45921916de02ac5cc8d57e1ca9882ccad900640a1b51c587de3291a2f15ad67e180b79b442fe4606de978f7a27591a41ffcd91116c50703c45531999c9d377a173c249ef747a60a81158c0d3ef709b9b5a38af61b6b5c9740c343f7322b6510a60797cb39148ba310413b688354bb0b2e395dbf3935fd0a797d7b5e94acab23a95c163238dd1bc9b8b420599a0efd4726e85a0783fc8506436c3eb89ee96008b0c9c5a2047a2415bbb5a2768d7c8d58384644d5473de96721b24a3fc82ee68cc0a3a43cc73467ec515a3ac1a79b9070f4e4aad61ac50c7b4e9b125f66cba026807cdad5a43e4a5cfa2ac521801616bb58ea068689c15afd4592b26545c3a8c638800a3429c32237a902f1a605458935391c4d352a211cb2122203f9ea38e3d44b29741502bb57c7850ffaf36ab0db72ac9c0fc0ba309661096bc550d86b442beca080c0602e02a54ed2171e58b0b82582c568a5b1407d8d35448cf907a43575aed4c5371595d1456f29778c892325d4d785a3a384a30b838e6b0d59990ca54ba52369c4faf835a2f50cbd504f7d38cdc4047bf7acae92090cf121180096a513dc4cadf290641ab6e4375aa477395b8902b74c39e62b945a09438d83b1d41ac2f204c4614425bed86e221c60c8520e1c3233e5ccb53c228c0d525fb7823d9d9c4337e36785eb61590794f9565b3dd2722a2834b536be157a307d928d7f910167a314b8705bdddc1b4c9c139a5320380910b1263b40a6c6065c84266a2c036a19d3a51f5edbb8eaf3cb1e8295ef1ab978f5306da9b11a5a3df473bbd2acca084a4c4bba0bc478630283b0e6910bde3052c6f58300703a6e9524381b4cc1b247236acc1c0bae6cb69c463c29811b04d93a589ba36d30c9b4d1fb234368a9b3e94abaf419a220af730917488bc9be585f7111c9a13a8544969bf3e397b1f2ceba0ca7f21785531a3f7856248f54a5bd854124b21e1e75c366e8b5293130bdb902db0a05e9803c3d7827d5cc26046815102c3713b4a14ef63aed3163319244995a6524dbabfaf93ed8a95e08641377683dd6b3b05084bf48f77d47904d09656d4a19b457d84bcfd77a4c433393bbb43f09931cf4896cf891990c9363202467b6193ea6b8bd493733235c93c118feb808b1d9b38cc7862c744342e2baeeec6299d0a21898aa9576ae61b2703a5b072521166f6693aa4b5e6148ad4e7c21a21a7972a0c8c3f986e95392ed2b15e51a5f2e5b90e4766320513e3bfa4d67688fb6c547147c47aa71c04095336b11b32b52a6c9d047a1357eece2688efb2045184653a480ef15a3fb8c4851d8c0407b24a87b55fd36af59b18fff38b183b6256e15c161395a46f62ce1b0af240319dec84d3aa04e2773ac289b393160683e901b2b622d615b2719b06cc12bae79fca101e737a91434c8e0828cc6a71b740216964a06a9952d9c54f24743b1b9c4fc9475554aa8a87719ccd7ae40374c87d8018937c7b6007e028b348e884d201087416396ec3237b61319e0f40e436a6a1dc75f2486a68c60c27f719d251a9d73b3de3bd91858d3f3d4043384f7ad42422b47b96bdd03b5556f8107232953dad801970157aa95971638e2908d55001d0020552cb65392fdab1ff61dd3b43c895fdf782c61bb6f05519f2b7d9e28facfd25e000d0012001004030804040105030805050108060601002b000706dada030403031a1a000100";
    req.set_fingerprint(Fingerprint::from_client_hello(hex::decode(tls_hex).unwrap(), fs::read_to_string("TOKEN").unwrap_or("".to_string())).unwrap());
    req.set_headers_json(headers).unwrap();
    let res = req.get("https://www.baidu.com", None).unwrap();
    println!("{}", res.text().unwrap());

    return;


    let mut req = ScReq::new()
        .with_alpn(ALPN::Http20)
        .with_verify(true)
        .with_timeout(Timeout::new_same(1000, 1))
        .with_key_log("2.log")
        .with_fingerprint(random_fingerprint("h5.moutai519.com.cn").unwrap())
        // .with_proxy(Proxy::try_from("http://36.150.202.148:10951").unwrap())
        // .with_mtls(certs, key)
        // .with_proxy(Proxy::try_from("http://127.0.0.1:10240").unwrap())
        ;

    let headers = json::object! {
        "User-Agent": "Mozilla/5.0 (Linux; Android 15; xuanyuan Build/VKQ1.250106.001.OS2.0.5.0.VNECNXM; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/128.0.6613.88 Mobile Safari/537.36 moutaiapp/1.9.7 device-id/bc823b4ef4840826d5df6bb059410d36 BS-DVID/UkGLUFZAqT06gye-0nF1683DRwZ2yujoY3kPcrdz5Ng9JA6i5g5XWsmJpNTq7PvYDiiCRTagsZn2LANM-RoIhDQ",
        "Accept": "*/*",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Dest": "document",
        "sec-fetch-user":"?1",
        "upgrade-insecure-requests":"1",
        "sec-ch-ua": "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Microsoft Edge\";v=\"120\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\"",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Accept-Encoding": "gzip,deflate",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        // "cookie":"_EDGE_V=1; MUIDB=184C10AD397866DF1A1607B038566708; MUID=184C10AD397866DF1A1607B038566708; _UR=QS=0&TQS=0&Pn=0; BFBUSR=BFBHP=0; MUIDB=184C10AD397866DF1A1607B038566708; SRCHD=AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF&AF=NOFORM; SRCHUID=V=2&GUID=EB7B9E5DE58F4D5690F6904732C24C7B&dmnchg=1; USRLOC=HS&ELOC=LAT=23.384721755981445|LON=113.44195556640625|N=%E7%99%BD%E4%BA%91%E5%8C%BA%EF%BC%8C%E5%B9%BF%E4%B8%9C%E7%9C%81|ELT=4|&HS=1; _RwBf=r&r&r&r&r=0&ilt=10&ihpd=5&ispd=3&rc=12&rb=0&rg=200&pc=12&mtu=0&rbb=0&clo=0&v=8&l=2026-03-15T07:00:00.0000000Z&lft=0001-01-01T00:00:00.0000000&aof=0&ard=0001-01-01T00:00:00.0000000&rwdbt=0&rwflt=0&rwaul2=0&g=&o=2&p=&c=&t=0&s=0001-01-01T00:00:00.0000000+00:00&ts=2026-03-15T14:03:35.7211444+00:00&rwred=0&wls=&wlb=&wle=&ccp=&cpt=&lka=0&lkt=0&aad=0&TH=&cid=0&gb=; SRCHUSR=DOB&DS&DS&DS&DS&DS=1&DOB=20260315; _EDGE_S=SID=357AA105805E678827ACB618817066E6; _SS=SID=357AA105805E678827ACB618817066E6; _HPVN=CS=eyJQbiI6eyJDbiI6MSwiU3QiOjAsIlFzIjowLCJQcm9kIjoiUCJ9LCJTYyI6eyJDbiI6MSwiU3QiOjAsIlFzIjowLCJQcm9kIjoiSCJ9LCJReiI6eyJDbiI6MSwiU3QiOjAsIlFzIjowLCJQcm9kIjoiVCJ9LCJBcCI6dHJ1ZSwiTXV0ZSI6dHJ1ZSwiTGFkIjoiMjAyNi0wMy0xNVQwMDowMDowMFoiLCJJb3RkIjowLCJHd2IiOjAsIlRucyI6MCwiRGZ0IjpudWxsLCJNdnMiOjAsIkZsdCI6MCwiSW1wIjozMCwiVG9ibiI6MH0=; SRCHHPGUSR=SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&V&SRCHLANG&SRCHLANG&SRCHLANG&V&SRCHLANG&SRCHLANG=zh-Hans&PREFCOL=0&BRW=NOTP&BRH=M&CW=150&CH=769&SCW=150&SCH=769&DPR=1.0&UTC=480&HV=1773588648&HVE=CfDJ8HAK7eZCYw5BifHFeUHnkJGC6_lT8f9GeruXx8zjPXuk-5GHkofYMoFErMkT8CTKKKsSt5O2HyGmjLyCEXbEREUmwCd8ZBlYMLSDZu1wZ-EI1LDuyIiI1tkP6Usyicm601qX3aJVYqVWUBn-t6h0ZWLiftm4aS627xFj1fE5PD-85i7BWTkhqG0uvaYzuSgB2A&BZA=0&PRVCW=150&PRVCH=769&B=0&EXLTT=7&V=CfDJ8HAK7eZCYw5BifHFeUHnkJGijeRjCoaCMaAnmznMvdEg2GXY8647Wb-7wnHNpePKXRO6KRQ_0cQc-onivd35uV-p-4g0MB0V_Z1ZpW-QSJe9zbPUG-Ks-kQMjzEl6GlLo6N0ciP51vkQdR-P-lCUH58&PR=1"
    };
    req.set_headers_json(headers).unwrap();
    let res = req.get("https://www.baidu.com", None).unwrap();
    println!("{}", res.header());
    // fs::write("data/coder/chunk_gzip.bin", res.raw_body()).unwrap();
    // println!("{} {:?}", res.raw_body().len(), res.raw_body());
    println!("{}", res.text().unwrap());
    // let res = req.get("https://117.89.181.21".sni("m.sogou.com"), None).unwrap();
    // println!("111={}", res.header());
    // let res = req.get("https://h5.moutai519.com.cn".sni("h5.moutai519.com.cn"), None).unwrap();
    // let res = req.get("https://aswbe.ana.co.jp/webapps/reservation/flight-search", None).await.unwrap();
    // req.re_conn(None).unwrap();
    // let res = req.get("https://aswbe.ana.co.jp/webapps/reservation/flight-search", None).await.unwrap();
    // let res = req.get("https://oauth.hubei.gov.cn:8443/", None).await.unwrap();
    // let res = req.get("https://104.18.34.137".sni("whatnot.com"), None).await.unwrap();
    // let res = req.get("https://150.139.229.223".sni("h5.moutai519.com.cn"), None).unwrap();
    // let res = req.get("https://117.89.181.21".sni("m.sogou.com"), None).unwrap();

}