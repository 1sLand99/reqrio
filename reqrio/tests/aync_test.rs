use reqrio::{AcReq, HttpStatus, ReqExt};
use reqtls::ALPN;

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
    let res = req.get("https://www.bing.com", None).await.unwrap();
    assert_eq!(res.header().status(), &HttpStatus::Found);

    let mut req = AcReq::new();
    let res = req.get("http://zwfw.hubei.gov.cn/web/user/uias_login.do?appCode=hbzwfw&gotoUrl=http%3A%2F%2Fzwfw.hubei.gov.cn%2Fwebview%2Fgrkj%2Fwelcome.html&p01=", None).await.unwrap();
    assert_eq!(res.header().status(), &HttpStatus::OK);
}


#[tokio::test]
async fn test_cipher() {
    //TLS1.3: TLS_AES_128_GCM_SHA256
    let mut req = AcReq::new();
    req.get("https://m.sogou.com", None).await.unwrap();
    //TLS1.3: TLS_AES_256_GCM_SHA384
    let mut req = AcReq::new();
    req.get("https://login.gjzwfw.gov.cn", None).await.unwrap();
    //TLS1.2: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    let mut req = AcReq::new();
    req.get("https://zwfw.hubei.gov.cn", None).await.unwrap();
    //TLS1.2: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    let mut req = AcReq::new();
    req.get("https://oauth.hubei.gov.cn", None).await.unwrap();
    //TLS1.2: TLS_RSA_WITH_AES_256_GCM_SHA384
    let mut req = AcReq::new();
    req.get("https://www.link114.cn/", None).await.unwrap();
    //TLS1.2: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    let mut req = AcReq::new();
    req.get("https://www.bing.com", None).await.unwrap();
}