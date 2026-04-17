use reqrio::{HttpStatus, ReqExt, ScReq};
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
    let res = req.get("http://zwfw.hubei.gov.cn/web/user/uias_login.do?appCode=hbzwfw&gotoUrl=http%3A%2F%2Fzwfw.hubei.gov.cn%2Fwebview%2Fgrkj%2Fwelcome.html&p01=", None).unwrap();
    assert_eq!(res.header().status(), &HttpStatus::OK);
}