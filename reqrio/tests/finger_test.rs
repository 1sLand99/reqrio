use std::{env, fs};
use std::sync::LazyLock;
use reqrio::*;
const JA3: &str = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,18-45-5-10-11-16-23-27-0-13-35-65281-43-51-17613,29-23-24,0";
const JA4: &str = "t13d1515h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,ff01_0804,0403,0401,0303,0402,080b,0201,0203,0202,0302,0502,0301,0503,0602,0806,0809";
static TOKEN: LazyLock<String> = LazyLock::new(|| fs::read_to_string("../TOKEN").unwrap_or(env::var("REQRIO_TOKEN").unwrap_or("".to_string())));

#[test]
fn test_ja3() {
    let fingerprint = Fingerprint::from_ja3(JA3, TOKEN.as_str()).unwrap();
    let mut req = ScReq::new().with_fingerprint(fingerprint);
    let resp = req.get("https://m.so.com", None).unwrap();
    assert_eq!(resp.header().status(), HttpStatus::OK)
}

#[cfg(feature = "aync")]
#[tokio::test]
async fn test_ja3_async() {
    let fingerprint = Fingerprint::from_ja3(JA3, TOKEN.as_str()).unwrap();
    let mut req = AcReq::new().with_fingerprint(fingerprint);
    let resp = req.get("https://m.so.com", None).await.unwrap();
    assert_eq!(resp.header().status(), HttpStatus::OK)
}


#[test]
fn test_ja4() {
    let fingerprint = Fingerprint::from_ja4(JA4, TOKEN.as_str()).unwrap();
    let mut req = ScReq::new().with_fingerprint(fingerprint);
    let resp = req.get("https://m.so.com", None).unwrap();
    assert_eq!(resp.header().status(), HttpStatus::OK)
}

#[cfg(feature = "aync")]
#[tokio::test]
async fn test_ja4_async() {
    let fingerprint = Fingerprint::from_ja4(JA4, TOKEN.as_str()).unwrap();
    let mut req = AcReq::new().with_fingerprint(fingerprint);
    let resp = req.get("https://m.so.com", None).await.unwrap();
    assert_eq!(resp.header().status(), HttpStatus::OK)
}

fn build_min_finger() -> Fingerprint {
    Fingerprint::new_h2(TlsFinger::Custom {
        record_version: Version::TLS_1_0,
        message_version: Version::TLS_1_2,
        suites: vec![
            CipherSuite::TLS_AES_128_GCM_SHA256,
            CipherSuite::TLS_AES_256_GCM_SHA384,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        ],
        extensions: vec![Extension::SupportedGroups(vec![NamedCurve::X25519])],
    }, H2Finger {
        setting: vec![],
        window_size: 0,
        weight: 0,
        priority: false,
    }, TOKEN.as_str()).unwrap()
}

#[test]
fn test_custom() {
    let mut req = ScReq::new().with_fingerprint(build_min_finger());
    let resp = req.get("https://m.so.com", None).unwrap();
    assert_eq!(resp.header().status(), HttpStatus::OK)
}

#[cfg(feature = "aync")]
#[tokio::test]
async fn test_custom_async() {
    let mut req = AcReq::new().with_fingerprint(build_min_finger());
    let resp = req.get("https://m.so.com", None).await.unwrap();
    assert_eq!(resp.header().status(), HttpStatus::OK)
}

#[test]
fn test_random() {
    let fingerprint = Fingerprint::random(TOKEN.as_str());
    let mut req = ScReq::new().with_fingerprint(fingerprint);
    let resp = req.get("https://m.so.com", None).unwrap();
    assert_eq!(resp.header().status(), HttpStatus::OK)
}

#[cfg(feature = "aync")]
#[tokio::test]
async fn test_random_async() {
    let fingerprint = Fingerprint::random(TOKEN.as_str());
    let mut req = ScReq::new().with_fingerprint(fingerprint);
    let resp = req.get("https://m.so.com", None).unwrap();
    assert_eq!(resp.header().status(), HttpStatus::OK)
}