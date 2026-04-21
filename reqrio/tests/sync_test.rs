use reqrio::{HttpStatus, ReqExt, ScReq, Timeout};
use reqtls::ALPN;

#[test]
fn test_tls12() {
    //h1
    let mut req = ScReq::new();
    req.get("https://www.baidu.com", None).unwrap();
    //h2
    let mut req = ScReq::new().with_alpn(ALPN::Http20);
    req.get("https://m.so.com", None).unwrap();
}

#[test]
fn test_tls13() {
    //h1
    let mut req = ScReq::new();
    req.get("https://m.sogou.com", None).unwrap();
    //h2
    let mut req = ScReq::new().with_alpn(ALPN::Http20);
    req.get("https://m.sogou.com", None).unwrap();
}


#[test]
fn test_auto_redirect() {
    let mut req = ScReq::new().with_alpn(ALPN::Http20).with_auto_redirect(false);
    let res = req.get("https://www.bing.com", None).unwrap();
    assert_eq!(res.header().status(), &HttpStatus::Found);

    //TLS_RSA_WITH_AES_128_CBC_SHA
    let mut req = ScReq::new();
    let res = req.get("https://www.github.com", None).unwrap();
    assert_eq!(res.header().status(), &HttpStatus::OK);
}

#[test]
fn test_cipher() {
    //TLS1.3: TLS_AES_128_GCM_SHA256
    let mut req = ScReq::new()
        .with_timeout(Timeout::longer())
        .with_auto_redirect(false);
    req.get("https://m.sogou.com", None).unwrap();
    //TLS1.3: TLS_AES_256_GCM_SHA384
    req.get("https://login.gjzwfw.gov.cn", None).unwrap();
    //TLS1.2: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    req.get("https://zwfw.hubei.gov.cn", None).unwrap();
    //TLS1.2: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    req.get("https://oauth.hubei.gov.cn:8443", None).unwrap();
    //TLS1.2: TLS_RSA_WITH_AES_256_GCM_SHA384
    req.get("https://www.link114.cn/", None).unwrap();
    //TLS1.2: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    req.get("https://www.bing.com", None).unwrap();
}

#[test]
fn test_hello_retry(){
    let mut req = ScReq::new().with_alpn(ALPN::Http20).with_auto_redirect(false);
    let res = req.get("https://bing.com/", None).unwrap();
    assert_eq!(res.header().status(), &HttpStatus::Move);
}