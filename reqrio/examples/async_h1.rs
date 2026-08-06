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

#[tokio::main]
async fn main() {
    #[cfg(feature = "log")]
    test_log();
    let mut timeout = Timeout::longer();
    timeout.set_handle_times(1);

    let mut req = AcReq::new()
        // .with_fingerprint(fingerprint)
        .with_timeout(timeout)
        .with_verify(true)
        .with_key_log("2.log")
        .with_auto_redirect(false)
        // .with_proxy(Proxy::Null)
        .with_verify(false)
        .with_alpn(ALPN::Http20)
        // .with_proxy(Proxy::try_from("http: //222.186.129.68:15265").unwrap())
        // .with_mtls(certs, key)
        // .with_proxy(Proxy::new_socks5("127.0.0.1",10279))
        .with_proxy(Proxy::new_http_plain("127.0.0.1", 10280))
        // .connect("https://104.18.34.137".sni("whatnot.com")).await.unwrap()
        ;
    let headers = json::object! {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
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
        "Accept-Encoding": "gzip,deflate,br,zstd",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        // "cookie":"_EDGE_V=1; MUIDB=184C10AD397866DF1A1607B038566708; MUID=184C10AD397866DF1A1607B038566708; _UR=QS=0&TQS=0&Pn=0; BFBUSR=BFBHP=0; MUIDB=184C10AD397866DF1A1607B038566708; SRCHD=AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF&AF=NOFORM; SRCHUID=V=2&GUID=EB7B9E5DE58F4D5690F6904732C24C7B&dmnchg=1; USRLOC=HS&ELOC=LAT=23.384721755981445|LON=113.44195556640625|N=%E7%99%BD%E4%BA%91%E5%8C%BA%EF%BC%8C%E5%B9%BF%E4%B8%9C%E7%9C%81|ELT=4|&HS=1; _RwBf=r&r&r&r&r=0&ilt=10&ihpd=5&ispd=3&rc=12&rb=0&rg=200&pc=12&mtu=0&rbb=0&clo=0&v=8&l=2026-03-15T07:00:00.0000000Z&lft=0001-01-01T00:00:00.0000000&aof=0&ard=0001-01-01T00:00:00.0000000&rwdbt=0&rwflt=0&rwaul2=0&g=&o=2&p=&c=&t=0&s=0001-01-01T00:00:00.0000000+00:00&ts=2026-03-15T14:03:35.7211444+00:00&rwred=0&wls=&wlb=&wle=&ccp=&cpt=&lka=0&lkt=0&aad=0&TH=&cid=0&gb=; SRCHUSR=DOB&DS&DS&DS&DS&DS=1&DOB=20260315; _EDGE_S=SID=357AA105805E678827ACB618817066E6; _SS=SID=357AA105805E678827ACB618817066E6; _HPVN=CS=eyJQbiI6eyJDbiI6MSwiU3QiOjAsIlFzIjowLCJQcm9kIjoiUCJ9LCJTYyI6eyJDbiI6MSwiU3QiOjAsIlFzIjowLCJQcm9kIjoiSCJ9LCJReiI6eyJDbiI6MSwiU3QiOjAsIlFzIjowLCJQcm9kIjoiVCJ9LCJBcCI6dHJ1ZSwiTXV0ZSI6dHJ1ZSwiTGFkIjoiMjAyNi0wMy0xNVQwMDowMDowMFoiLCJJb3RkIjowLCJHd2IiOjAsIlRucyI6MCwiRGZ0IjpudWxsLCJNdnMiOjAsIkZsdCI6MCwiSW1wIjozMCwiVG9ibiI6MH0=; SRCHHPGUSR=SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&V&SRCHLANG&SRCHLANG&SRCHLANG&V&SRCHLANG&SRCHLANG=zh-Hans&PREFCOL=0&BRW=NOTP&BRH=M&CW=150&CH=769&SCW=150&SCH=769&DPR=1.0&UTC=480&HV=1773588648&HVE=CfDJ8HAK7eZCYw5BifHFeUHnkJGC6_lT8f9GeruXx8zjPXuk-5GHkofYMoFErMkT8CTKKKsSt5O2HyGmjLyCEXbEREUmwCd8ZBlYMLSDZu1wZ-EI1LDuyIiI1tkP6Usyicm601qX3aJVYqVWUBn-t6h0ZWLiftm4aS627xFj1fE5PD-85i7BWTkhqG0uvaYzuSgB2A&BZA=0&PRVCW=150&PRVCH=769&B=0&EXLTT=7&V=CfDJ8HAK7eZCYw5BifHFeUHnkJGijeRjCoaCMaAnmznMvdEg2GXY8647Wb-7wnHNpePKXRO6KRQ_0cQc-onivd35uV-p-4g0MB0V_Z1ZpW-QSJe9zbPUG-Ks-kQMjzEl6GlLo6N0ciP51vkQdR-P-lCUH58&PR=1"
    };
    req.set_headers_json(headers).unwrap();
    // req.set_url("https://shopee.tw/").await.unwrap();
    // req.set_url("https://127.0.0.1:3453/v1/api/tlsReq").await.unwrap();
    // req.set_json(data);
    // req.set_auto_redirect(false);
    // req.set_url("http://zwfw.hubei.gov.cn/web/user/uias_login.do?appCode=hbzwfw&gotoUrl=http%3A%2F%2Fzwfw.hubei.gov.cn%2Fwebview%2Fgrkj%2Fwelcome.html&p01=").await.unwrap();
    // req.set_url("https://127.0.0.1:7878").await.unwrap();
    // req.set_url("https://www.jetstar.com").await.unwrap();
    // req.set_url("https://m1.pxb7.com/api/search/h5/product/selectSearchPageList").await.unwrap();
    // req.set_url("https://www.link114.cn/").await.unwrap();
    //
    // req.set_url("https://accounts.pcid.ca/login").await.unwrap();
    // req.set_url("https://xxbg.snssdk.com/fdsf/dsfsdfkdsjfk").await.unwrap();
    // req.set_url("https://www.toutiao.com/article/7600224020776239658/?log_from=99ab1fa2b852c_1769590891442&wid=1769590984039").await.unwrap();
    // req.set_url("https://www.sogou.com").await.unwrap();
    // req.set_url("https://cn.bing.com/search?q=site%EF%BC%9Asite：wLLyn.com&first=0&FORM=PERE2").await.unwrap();
    // req.set_proxy(Proxy::new_socks5("127.0.0.1", 10279));
    // req.set_url("https://m.baidu.com").await.unwrap();
    // req.set_url("https://www.sephora.com/").await.unwrap();
    // req.set_url("https://doc.rust-lang.org/").await.unwrap();
    // req.set_url("https://tls.123408.xyz/api/clean").await.unwrap();
    // req.set_url("https://mcs-mimp-web.sf-express.com/mcs-mimp/sendValidCode").await.unwrap()
    // req.set_url("https://jetstar.com").await.unwrap();
    // req.set_url("https://127.0.0.1:8000").await.unwrap();
    // req.set_auto_redirect(false);
    // req.set_url("https://oauth.hubei.gov.cn:8443/").await.unwrap();
    req.set_auto_redirect(false);
    // let res = req.get("https://dns.alidns.com/resolve?name=crypto.cloudflare.com&type=HTTPS", None).await.unwrap();
    // let res=req.get("https://www.link114.cn/",None).await.unwrap();
    // let res = req.get("https://www.bing.com".params(json::object! {}), vec![0u8; 0].ty(Application::Json)).await.unwrap();
    // let res = req.get("https://117.89.181.21".sni("m.sogou.com"), None).await.unwrap();
    // let url = Url::try_from("https://cn.bing.com/").unwrap();
    // let url = "https://113.108.215.122/xhr/front/trade/priority/rushPurchase/hot/branch/one".sni("h5.moutai519.com.cn").unwrap(); //
    // let url: Url = "https://www.bing.com".try_into().unwrap();
    // let url: Url = "https://www.bing.com".try_into().unwrap();
    let url = "https://shop.lululemon.com/help/orders/gift-card-balance";
    // req.re_conn(Some(&url)).await.unwrap();
    let resp = req.get(url, None).await.unwrap();
    // let resp = req.post(url.clone(), None).await.unwrap();
    println!("{} {}", resp.header(), resp.as_bytes().len());
    // req.re_conn(None).await.unwrap();
    // let resp = req.get(url, None).await.unwrap();
    // println!("{}", resp.header());
    // println!("{}", resp.as_text().unwrap());

    // println!("{} {}", res1.header(), res2.header());
    // let res = req.get("https://m.sogou.com", None).await.unwrap();
    // let session=req.stream_mut().tls_session().cloned();
    // req.set_tls_session(session);
    // let res = req.get("https://150.139.229.223".sni("h5.moutai519.com.cn"), None).await.unwrap();
    // let res = req.get("https://aswbe.ana.co.jp/webapps/reservation/flight-search", None).await.unwrap();
    // req.re_conn(None).await.unwrap();
    // let res = req.get("https://aswbe.ana.co.jp/webapps/reservation/flight-search", None).await.unwrap();
    // let res = req.send("https://oauth.hubei.gov.cn:8443/", None).await.unwrap();
    // let res = req.get("https://104.18.34.137".sni("whatnot.com"), None).await.unwrap();
    // let res = req.get("https://150.139.229.223".sni("h5.moutai519.com.cn"), None).await.unwrap();
    // loop {

    //     println!("{}", res.header().status());
    //
    // }

    // let res=req.get("https://h5.moutai519.com.cn",None).await.unwrap();
    // let res = req.get("https://m.baidu.com", None).await.unwrap();
    // println!("{}", res.json().unwrap().pretty())
    // println!("{:#?}", req.header().cookies());
    // println!("{}",res.text().unwrap());
    // req.set_url("https://m.so.com").await.unwrap();
    // req.set_url("https://im.jinritemai.com/").await.unwrap();
    // req.set_auto_redirect(false);
    // req.set_url("https://cn.bing.com/AS/Suggestions?pt=page.home&qry=&csr=1&pths=1&zis=1&pf=1&cvid=AFEA02EAF9E449A99970476597AE6CED").await.unwrap();
    // req.set_text("sfssdfsfsdfdf");
    // println!("{:?}",String::from_utf8(fs::read("/home/xl/1/ca.crt").unwrap()).unwrap());
    // let data = json::object! {"test_key":"test_value"};
    // let file = HttpFile::new_bytes_data(data, fs::read("/home/xl/1/ca.crt").unwrap());
    // req.set_files(file).unwrap();
    // req.set_data(data);
    // println!("{}", req.h1_raw_string().unwrap());
    // let res = req.get().await.unwrap();
    // println!("{} {:#?}", res.header().status(), req.header().cookies());
    // let params = json::object! {
    //     format:"{\\json",
    //     ecount:20,
    //     efirst:0
    // };
    // let url = "https://cn.bing.com/hp/api/v1/carousel".to_string();
    // // println!("{}", url);
    // let res = req.get(url.params(params), None).await.unwrap();
    // req.set_url("https://cn.bing.com/notifications/render?bnptrigger=%7B%22PartnerId%22%3A%22HomePage%22%2C%22IID%22%3A%22Bnp%22%2C%22Attributes%22%3A%7B%22RawRequestURL%22%3A%22%2F%22%7D%7D&IG=AFEA02EAF9E449A99970476597AE6CED&IID=Bnp").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/web/xlsc.aspx?dl=1&f=8").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/hp/api/model").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/sa/simg/favicon-trans-bg-blue-mg-png.png").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/web/xlsc.aspx?dl=1&f=8").await.unwrap();
    // let res = req.get().await.unwrap();
    // let res = req.get().await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/AS/Suggestions?pt=page.home&qry=&csr=1&pths=1&zis=1&pf=1&cvid=AFEA02EAF9E449A99970476597AE6CED").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/hp/api/v1/carousel?&format=json&ecount=20&efirst=0&&").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/notifications/render?bnptrigger=%7B%22PartnerId%22%3A%22HomePage%22%2C%22IID%22%3A%22Bnp%22%2C%22Attributes%22%3A%7B%22RawRequestURL%22%3A%22%2F%22%7D%7D&IG=AFEA02EAF9E449A99970476597AE6CED&IID=Bnp").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/web/xlsc.aspx?dl=1&f=8").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/hp/api/model").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/sa/simg/favicon-trans-bg-blue-mg-png.png").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/web/xlsc.aspx?dl=1&f=8").await.unwrap();
    // let res = req.get().await.unwrap();
    // let res = req.get().await.unwrap();
    // let res = req.get().await.unwrap();
    // println!("{}", res.header());

}