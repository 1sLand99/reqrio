use reqrio::{AcReq, Buffer, Fingerprint, HttpStatus, ReqExt};
use reqtls::{CipherSuite, EcPointFormat, ExtensionType, NamedCurve, SignatureAlgorithm, TlsFinger, Version, WriteExt, ALPN};

#[tokio::test]
async fn test_tls12() {
    //h1
    let mut req = AcReq::new();
    req.get("https://www.baidu.com", None).await.unwrap();
    //h2
    let mut req = AcReq::new().with_alpn(ALPN::Http20);
    req.get("https://m.so.com", None).await.unwrap();
}

#[tokio::test]
async fn test_tls13() {
    //h1
    let mut req = AcReq::new();
    req.get("https://m.sogou.com", None).await.unwrap();
    //h2
    let mut req = AcReq::new().with_alpn(ALPN::Http20);
    req.get("https://m.sogou.com", None).await.unwrap();
}


#[tokio::test]
async fn test_auto_redirect() {
    let mut req = AcReq::new().with_alpn(ALPN::Http20).with_auto_redirect(false);
    let res = req.get("https://m.so.com/jump?u=https%3A%2F%2Fmusic.163.com%2Fprogram%3Fid%3D901456263&m=824610&from=m.so.com&monitor=pro%3Dm_so%26pid%3Dresult%26u%3Dhttps%253A%252F%252Fm.so.com%252Fs%252F%26guid%3D14911145.7415413442912131315.1776792324389.8155%26mbp%3D0%26q%3Dewrwe%26pq%3D%26ls%3D%26abv%3D3984-control%252C3759-cpc_m_short_video_vertical_1%26ablist%3D%26sid%3D2548d9cd0087145e8d437af844fa059c%26qid%3D%26src%3Dmsearch_next_input%26srcg%3Dhome_next%26userid%3D%26nid%3D%26version%3D%26category%3D%26nettype%3Dunknown%26nav%3D%26chl%3D%26bv%3D%26adv_t%3D%26end%3D0%26bucketid%3D240001%252C350001%252C530001%252C540001%252C600000%252C750001%252C830001%252C850014%252C920001%252C1230009%252C1330001%252C3030000%252C4130001%252C4260003%252C4700000%252C4770000%252C4810001%252C4970002%252C5010009%252C5120000%252C5150001%252C5560001%252C5790000%252C5810001%252C5910001%252C6000000%252C6330024%252C6480000%252C6490000%252C6570003%252C6620003%252C6920004%252C7170010%252C7190027%252C7970001%252C8060001%252C8080002%252C8100011%252C8190003%252C8220000%252C8310003%252C8480001%252C8570012%252C8640000%252C8720008%252C9000027%252C9110000%252C9240006%252C9270010%252C9560006%252C9630014%252C10820000%252C10950002%252C11090000%252C11140000%252C11180001%252C11460000%252C11500004%252C11750001%26pn%3D1%26bzv%3D584d8cd4518f3435%26mod%3Dog%26pos%3D6%26type%3Dwap%26official%3D0%26pcurl%3Dhttps%253A%252F%252Fmusic.163.com%252Fprogram%253Fid%253D901456263%26data-md-b%3Dtitle%26url_fp%3DCgYIARADGAQ%253D%26screen%3D3%26scrTime%3D3%26af%3D0%26clicktype%3Dlink%26value%3Dhttps%253A%252F%252Fmusic.163.com%252Fprogram%253Fid%253D901456263%26t%3D1776792353084", None).await.unwrap();
    assert_eq!(res.header().status(), &HttpStatus::Found);

    //TLS_RSA_WITH_AES_128_CBC_SHA
    let mut req = AcReq::new();
    let res = req.get("https://m.so.com/jump?u=https%3A%2F%2Fmusic.163.com%2Fprogram%3Fid%3D901456263&m=824610&from=m.so.com&monitor=pro%3Dm_so%26pid%3Dresult%26u%3Dhttps%253A%252F%252Fm.so.com%252Fs%252F%26guid%3D14911145.7415413442912131315.1776792324389.8155%26mbp%3D0%26q%3Dewrwe%26pq%3D%26ls%3D%26abv%3D3984-control%252C3759-cpc_m_short_video_vertical_1%26ablist%3D%26sid%3D2548d9cd0087145e8d437af844fa059c%26qid%3D%26src%3Dmsearch_next_input%26srcg%3Dhome_next%26userid%3D%26nid%3D%26version%3D%26category%3D%26nettype%3Dunknown%26nav%3D%26chl%3D%26bv%3D%26adv_t%3D%26end%3D0%26bucketid%3D240001%252C350001%252C530001%252C540001%252C600000%252C750001%252C830001%252C850014%252C920001%252C1230009%252C1330001%252C3030000%252C4130001%252C4260003%252C4700000%252C4770000%252C4810001%252C4970002%252C5010009%252C5120000%252C5150001%252C5560001%252C5790000%252C5810001%252C5910001%252C6000000%252C6330024%252C6480000%252C6490000%252C6570003%252C6620003%252C6920004%252C7170010%252C7190027%252C7970001%252C8060001%252C8080002%252C8100011%252C8190003%252C8220000%252C8310003%252C8480001%252C8570012%252C8640000%252C8720008%252C9000027%252C9110000%252C9240006%252C9270010%252C9560006%252C9630014%252C10820000%252C10950002%252C11090000%252C11140000%252C11180001%252C11460000%252C11500004%252C11750001%26pn%3D1%26bzv%3D584d8cd4518f3435%26mod%3Dog%26pos%3D6%26type%3Dwap%26official%3D0%26pcurl%3Dhttps%253A%252F%252Fmusic.163.com%252Fprogram%253Fid%253D901456263%26data-md-b%3Dtitle%26url_fp%3DCgYIARADGAQ%253D%26screen%3D3%26scrTime%3D3%26af%3D0%26clicktype%3Dlink%26value%3Dhttps%253A%252F%252Fmusic.163.com%252Fprogram%253Fid%253D901456263%26t%3D1776792353084", None).await.unwrap();
    assert_eq!(res.header().status(), &HttpStatus::OK);
}

fn build_finger(suites: Vec<CipherSuite>, groups: Vec<NamedCurve>) -> Fingerprint {
    Fingerprint {
        tls: TlsFinger::Custom {
            suites,
            groups,
            algorithms: vec![
                SignatureAlgorithm::RSA_PKCS1_SHA1.into(),
                SignatureAlgorithm::RSA_PKCS1_SHA256.into(),
                SignatureAlgorithm::RSA_PKCS1_SHA384.into(),
                SignatureAlgorithm::RSA_PKCS1_SHA512.into(),
                SignatureAlgorithm::ECDSA_SECP256R1_SHA256.into(),
                SignatureAlgorithm::ECDSA_SECP384R1_SHA384.into(),
                SignatureAlgorithm::ECDSA_SECP521R1_SHA512.into(),
                SignatureAlgorithm::RSA_PSS_PSS_SHA256.into(),
                SignatureAlgorithm::RSA_PSS_PSS_SHA384.into(),
                SignatureAlgorithm::RSA_PSS_PSS_SHA512.into(),
                SignatureAlgorithm::RSA_PSS_RSAE_SHA256.into(),
                SignatureAlgorithm::RSA_PSS_RSAE_SHA384.into(),
                SignatureAlgorithm::RSA_PSS_RSAE_SHA512.into(),
            ],
            versions: vec![Version::TLS_1_3, Version::TLS_1_2],
            ec_formats: vec![EcPointFormat::UNCOMPRESSED],
            compress_methods: vec![],
            extensions: vec![
                ExtensionType::StatusRequest,
                ExtensionType::SupportedGroup,
                ExtensionType::EcPointFormats,
                ExtensionType::SignatureAlgorithms,
                ExtensionType::SignedCertificateTimestamp,
                ExtensionType::ExtendMasterSecret,
                ExtensionType::CompressionCertificate,
                ExtensionType::SessionTicket,
                ExtensionType::SupportedVersions,
                ExtensionType::PskKeyExchangeMode,
                ExtensionType::KeyShare,
                ExtensionType::ApplicationSetting,
                ExtensionType::ServerName,
                ExtensionType::ApplicationLayerProtocolNegotiation
            ],
        },
        legal_subscript: Buffer::with_capacity(0).check_subscription("2f-o7ffnfc-j2f7q7n-k7ffnfc-m423p26-k").unwrap_or(1),
        ..Default::default()
    }
}

///ECDHE_RSA
#[tokio::test]
async fn test_ecdhe_rsa() {
    let fingerprint = build_finger(
        vec![CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.into()],
        vec![NamedCurve::X25519.into()], );
    let mut req = AcReq::new().with_fingerprint(fingerprint);
    req.get("https://m.so.com", None).await.unwrap();
    let fingerprint = build_finger(
        vec![CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.into()],
        vec![NamedCurve::X25519.into()], );
    let mut req = AcReq::new().with_fingerprint(fingerprint);
    req.get("https://m.so.com", None).await.unwrap();
    let fingerprint = build_finger(
        vec![CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256.into()],
        vec![NamedCurve::X25519.into()], );
    let mut req = AcReq::new().with_fingerprint(fingerprint);
    req.get("https://m.so.com", None).await.unwrap();
    let fingerprint = build_finger(
        vec![CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.into()],
        vec![NamedCurve::X25519.into()], );
    let mut req = AcReq::new().with_fingerprint(fingerprint);
    req.get("https://m.so.com", None).await.unwrap();
    let fingerprint = build_finger(
        vec![CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA.into()],
        vec![NamedCurve::X25519.into()], );
    let mut req = AcReq::new().with_fingerprint(fingerprint);
    req.get("https://m.so.com", None).await.unwrap();
    // let fingerprint = build_finger(
    //     vec![CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256.into()],
    //     vec![NamedCurve::X25519.into()], );
    // let mut req = ScReq::new().with_fingerprint(fingerprint);
    // req.get("https://m.so.com", None).unwrap();

    // let fingerprint = build_finger(
    //     vec![CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384.into()],
    //     vec![NamedCurve::X25519.into()], );
    // let mut req = ScReq::new().with_fingerprint(fingerprint);
    // req.get("https://m.so.com", None).unwrap();
}

///RSA
#[tokio::test]
async fn test_rsa() {
    let fingerprint = build_finger(
        vec![CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA.into()],
        vec![NamedCurve::X25519.into()], );
    let mut req = AcReq::new().with_fingerprint(fingerprint);
    req.get("https://m.baidu.com", None).await.unwrap();
    let fingerprint = build_finger(
        vec![CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA.into()],
        vec![NamedCurve::X25519.into()], );
    let mut req = AcReq::new().with_fingerprint(fingerprint);
    req.get("https://m.baidu.com", None).await.unwrap();
}

#[tokio::test]
async fn test_tls13_cipher() {
    let fingerprint = build_finger(
        vec![CipherSuite::TLS_AES_128_GCM_SHA256.into()],
        vec![NamedCurve::X25519.into()], );
    let mut req = AcReq::new().with_fingerprint(fingerprint);
    req.get("https://m.sogou.com", None).await.unwrap();
    let fingerprint = build_finger(
        vec![CipherSuite::TLS_AES_256_GCM_SHA384.into()],
        vec![NamedCurve::X25519.into()], );
    let mut req = AcReq::new().with_fingerprint(fingerprint);
    req.get("https://m.sogou.com", None).await.unwrap();
    let fingerprint = build_finger(
        vec![CipherSuite::TLS_CHACHA20_POLY1305_SHA256.into()],
        vec![NamedCurve::X25519.into()], );
    let mut req = AcReq::new().with_fingerprint(fingerprint);
    req.get("https://m.sogou.com", None).await.unwrap();
}


#[tokio::test]
async fn test_hello_retry() {
    let mut req = AcReq::new().with_alpn(ALPN::Http20).with_auto_redirect(false);
    let res = req.get("https://bing.com/", None).await.unwrap();
    assert_eq!(res.header().status(), &HttpStatus::Move);
}