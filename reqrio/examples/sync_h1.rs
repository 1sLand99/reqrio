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
            CipherSuite::from(REVERSED[rand::random::<usize>() % REVERSED.len()]),
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
    let res = ScReq::new().get("http://127.0.0.1:12354/json/version", None).unwrap();
    println!("{}", res.raw_string());

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