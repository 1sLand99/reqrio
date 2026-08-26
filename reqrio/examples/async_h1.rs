use reqrio::*;
use std::os::raw::c_int;
use std::fs;

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
    set_max_level(LevelFilter::Trace);
}


#[tokio::main]
async fn main() {
    #[cfg(feature = "log")]
    test_log();
    Buffer::check_subscription(fs::read_to_string("TOKEN").unwrap()).unwrap();
    let fingerprint = Fingerprint::from_hex(
        "160101006e0100006a0101c7ec7194d530ff19db95632fa75e775e6a19b321f7d72dadc3610d1e28406b78208eb49beda186277455c7595ac2042ae09b8e7df712fff6bdb40085d390a875b60002e0130100001f6a6a000000000012001000000d746573742e676d73736c2e636efafa000100",
        fs::read_to_string("TOKEN").unwrap(),
    ).unwrap();

    let t = Time::now();
    let mut timeout = Timeout::longer();
    timeout.set_handle_times(1);

    let mut headers = json::object! {
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
        "content-length": "0"
        // "cookie":"_EDGE_V=1; MUIDB=184C10AD397866DF1A1607B038566708; MUID=184C10AD397866DF1A1607B038566708; _UR=QS=0&TQS=0&Pn=0; BFBUSR=BFBHP=0; MUIDB=184C10AD397866DF1A1607B038566708; SRCHD=AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF&AF=NOFORM; SRCHUID=V=2&GUID=EB7B9E5DE58F4D5690F6904732C24C7B&dmnchg=1; USRLOC=HS&ELOC=LAT=23.384721755981445|LON=113.44195556640625|N=%E7%99%BD%E4%BA%91%E5%8C%BA%EF%BC%8C%E5%B9%BF%E4%B8%9C%E7%9C%81|ELT=4|&HS=1; _RwBf=r&r&r&r&r=0&ilt=10&ihpd=5&ispd=3&rc=12&rb=0&rg=200&pc=12&mtu=0&rbb=0&clo=0&v=8&l=2026-03-15T07:00:00.0000000Z&lft=0001-01-01T00:00:00.0000000&aof=0&ard=0001-01-01T00:00:00.0000000&rwdbt=0&rwflt=0&rwaul2=0&g=&o=2&p=&c=&t=0&s=0001-01-01T00:00:00.0000000+00:00&ts=2026-03-15T14:03:35.7211444+00:00&rwred=0&wls=&wlb=&wle=&ccp=&cpt=&lka=0&lkt=0&aad=0&TH=&cid=0&gb=; SRCHUSR=DOB&DS&DS&DS&DS&DS=1&DOB=20260315; _EDGE_S=SID=357AA105805E678827ACB618817066E6; _SS=SID=357AA105805E678827ACB618817066E6; _HPVN=CS=eyJQbiI6eyJDbiI6MSwiU3QiOjAsIlFzIjowLCJQcm9kIjoiUCJ9LCJTYyI6eyJDbiI6MSwiU3QiOjAsIlFzIjowLCJQcm9kIjoiSCJ9LCJReiI6eyJDbiI6MSwiU3QiOjAsIlFzIjowLCJQcm9kIjoiVCJ9LCJBcCI6dHJ1ZSwiTXV0ZSI6dHJ1ZSwiTGFkIjoiMjAyNi0wMy0xNVQwMDowMDowMFoiLCJJb3RkIjowLCJHd2IiOjAsIlRucyI6MCwiRGZ0IjpudWxsLCJNdnMiOjAsIkZsdCI6MCwiSW1wIjozMCwiVG9ibiI6MH0=; SRCHHPGUSR=SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&V&SRCHLANG&SRCHLANG&SRCHLANG&V&SRCHLANG&SRCHLANG=zh-Hans&PREFCOL=0&BRW=NOTP&BRH=M&CW=150&CH=769&SCW=150&SCH=769&DPR=1.0&UTC=480&HV=1773588648&HVE=CfDJ8HAK7eZCYw5BifHFeUHnkJGC6_lT8f9GeruXx8zjPXuk-5GHkofYMoFErMkT8CTKKKsSt5O2HyGmjLyCEXbEREUmwCd8ZBlYMLSDZu1wZ-EI1LDuyIiI1tkP6Usyicm601qX3aJVYqVWUBn-t6h0ZWLiftm4aS627xFj1fE5PD-85i7BWTkhqG0uvaYzuSgB2A&BZA=0&PRVCW=150&PRVCH=769&B=0&EXLTT=7&V=CfDJ8HAK7eZCYw5BifHFeUHnkJGijeRjCoaCMaAnmznMvdEg2GXY8647Wb-7wnHNpePKXRO6KRQ_0cQc-onivd35uV-p-4g0MB0V_Z1ZpW-QSJe9zbPUG-Ks-kQMjzEl6GlLo6N0ciP51vkQdR-P-lCUH58&PR=1"
    };
    let mut tls = json::object! {
        "id": 144,
        "typ": "VIP",
        "tls_finger": "16030107120100070e0303faf22de89f4672f79a363ed9950e2b2b807cc41731b8e20bbf6de690a8f6daeb2005d7f96eb8631dc9040260d188ce0f049902feac7c5acd167a0a6edb207b051400200a0a130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035010006a5aaaa000044cd00050003026832002300000010000e000c02683208687474702f312e31000d0012001004030804040105030805050108060601003304ef04edbaba00010011ec04c0afcc467841082d14b0c095b652f67e1960abf3cbca1b378390a35262758baf901347265621f097ac26b4fac500d91891a4521d39643e542b7aedc5ce916a7fc8e618e0e397beb07d880a8fc780c922221aab206f4cba6411391da586c3e861847a7c82ca12783b67038e011eb274065bc90585233619098335934ed276695d11c0aed026f6e0bb1c29508408771fd50dbfb747faa60d53d63a8a66c8aa89824fc89b9b94ca958a2ed1b28d4660553260b6762a5309e94208a28793a8650288478218b22e1174f524a4a091568f9424dee609d7885197eac3e15800a8e41ac4e852cdb6ad210a3fd9256959901254f7cce9a83441554e5136c81025467b4602c2e6583a8a354226c88737c5c10b5496290d1ad12ee8266ddcd59838f268bf34a55fb09fb1390d3ac02a05ba40d352554290972d01ae300b8a7aba19c543c4dea594aacbc19659b42965ca3d8c048cd22689dac43dab33cfeb40c4768798da4ccfa9c281e243aa0cc663a05fdb646e63528c345456004351f682077a47328bcb791fcc9d99086f653a6c80d06f8a681e26160a39057905968926182f04ea906a7c8af1178dc8c233abc5bff671ba37976fea324b82272e775658346a89538c9152947c6cd4b08b584ee50c93c48c5dd9bcc97c5c95b2f77d58205b489433b3d2b14fb81f2ed367f0285b4fe15f8d11060124b01ff79c09b0c6f154421358cf56bbb2e3162ab79205e6883a77267f747bb50089a819bc041c8baa94a61355c881fcfc4470968602892517820bdb2379749c4b195c7fac395a015041d0a11f3b177140aa824d33a57ab709b4aa1bb3cab56566af99f25a16a34bd2a992c40b599db05726021be4b88e28021914633a627abe0e703b847a6d42c2960d9200f8c91f85511ab5734dda48012d5267e74cc844f58a8513607c4471eaa001ac533955714660871cb5347ee53914941075d6385d7ca07d112c049bd1bfc202c6295103298a9ebc3a59df172779a9a517422b7476632ccb4061d07fefc1a1aaaa81baf86cc0e97e6d370c3ed265a649735e75741ab81b28d10c14c3312a808bbf8534357c141e166b17ea096aa4750d2071b4fac4cc43aa2e26a4173926e4348698a55e21bbb73477b528527c077a0f2eab5cdb71513ef9021d41297616a6279b57ed832c5bca0531bc353ae9a1d7930ed1da1151b76ef5f9ab69047cae8786fd02bbc668b056f83035bb84195a7a7bc155f2247566bba1f1296ebfec7560b94d13e240c55b721140218833889461560b261841d4358458b02d547f283a0f093668344057d69373ec0c5d3e700106dc0efe6b2826408df413243b4c551d5ba1c31b7fa1a53cd8d71c107431af31478d10689a734c1ca6357b5b8533861334f26ec6313c3a6c58b9b7b6138cbc6eb448712a9d97d16d4c89ac21e14acecc680ce695c23b5002ac98ff1a7735d69ee854bb745454905abb92175355923094438d26ba937e07395b90c872710f94419bef60a858899bc9744d0e129457e26fa990ba8bdb3f87712fe31a15902093ca6a0898d48356946e93f13c2627bfed1185cf087288478dc0113c0bb35e3fd93675a872ce00178f3bbc3106600b3bcb298670a806bd2a2ac4e01240e5a2c8bf5f9c41c0b6ad89d82b4f93b2421c6e5ddbf6b66ccf3e7285005f2b881a55dff1b54374cc5c94f84754588b1719fbd956a0fe79a3f9cdfebc44001d00202f9589897f661b2055798fc08a4e4402b9c84d8cff9fdd5a9b4943f9d4492f72000500050100000000000b0002010000120000fe0d011a0000010001c800208762f2fb60545a90018cb4f4df491e779555ca038a21a2f756a8ddc4ed627d6600f0e6f206542cf4b238f4b07fcf5b47cca984368ee6519ac3a6206974f6434962a6c72048c75d1020a05d0bd29b7288ec8304b52df1c21772d7bdb3e9b1fc719450e7d452d6c1937c20ab4baa13e1440ccf1e205a740080995618126ff204ad82f0008527460a5016fd5b2f141f2385e9005c2732296778d2ade2e471716d39f5976f09bd3413342c820ffd253d593fd9860015c6f2f48d2746790e01a7ecdc64ce3d5ef52e0d8b6e20808120aa2897c8e41a877fce4a54dcc7668845e12c475712bee7d61ce5d779640216ffa0fbfed56351c4f19b3d9bce7fd16fabe0c5b83838f3c1de8e0db2a51c890ba98afc7f7f0800170000000a000c000ababa11ec001d00170018ff01000100002d00020101001b0003020002002b000706baba030403030000000e000c0000093338686d7a672e636ebaba0001001603030046100000424104ff635373fbbfbc37444a2026372f57fd06c5205bacfe32b61261a9d29bf1fca57f91ef22cb2ba46af8cf9ae7c3123f56634099af297dcd30835cd81664005fb9140303000101",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
        "sec_ch_ua": "\"Google Chrome\";v=\"137\", \"Chromium\";v=\"137\", \"Not/A)Brand\";v=\"24\"",
        "sec_ch_ua_mobile": "?0",
        "sec_ch_ua_platform": "\"Windows\"",
        // "sec_ch_ua_bitness": "\"64\"",
        // "sec_ch_ua_arch": "\"x86\"",
        // "sec_ch_ua_full_version": "\"137.0.7151.69\"",
        // "sec_ch_ua_full_version_list": "\"Google Chrome\";v=\"137.0.7151.69\", \"Chromium\";v=\"137.0.7151.69\", \"Not/A)Brand\";v=\"24.0.0.0\"",
        // "sec_ch_ua_model": "\"\"",
        // "sec_ch_ua_platform_version": "\"10.0.0\""
      };
    // tls.remove("id");
    // tls.remove("typ");
    // let d = tls.remove("tls_finger").dump();
    // let mut fingerprint = Fingerprint::from_hex_all(d, fs::read_to_string("TOKEN").unwrap()).unwrap();
    // fingerprint.h2_mut().window_size = 15663105;
    // headers.update_by(tls).unwrap();
    let cert = Certificate::from_der(hex::decode("308201cd30820170a00302010202060172a730a372300c06082a811ccf5501837505003049310b300906035504061302434e310e300c060355040a1305474d53534c3110300e060355040b1307504b492f534d32311830160603550403130f526f6f74434120666f7220546573743022180f32303135313233313136303030305a180f32303335313233303136303030305a3049310b300906035504061302434e310e300c060355040a1305474d53534c3110300e060355040b1307504b492f534d32311830160603550403130f526f6f74434120666f7220546573743059301306072a8648ce3d020106082a811ccf5501822d03420004e3f9aa5894bf9d7565d9efe98565764919b70915750df85b33cfa86e99ec9664fe2a104af6374f9a65dc28ff6d5fb76df6ca8d233cbcddb1c281dbad734905d2a33e303c30190603551d0e041204109c69ec0fba1a39c5afe824ebb29c1204300f0603551d130101ff040530030101ff300e0603551d0f0101ff0404030200c6300c06082a811ccf5501837505000349003046022100849d6e41950874be6b0e2f14a85d873fef3b3efb05b215cd6d9c11c4351e04970221008d4bc2eea29f5aee7e5661cec796ba55f07084dfddb9bf6395f58355c5590507").unwrap()).unwrap();
    let mut req = AcReq::new()
        .with_fingerprint(fingerprint)
        .with_timeout(timeout)
        .with_verify(true)
        .with_key_log("2.log")
        .with_auto_redirect(false)
        // .with_proxy(Proxy::Null)
        .with_verify(true)
        .with_alpn(ALPN::Http20)
        .with_header_json(headers).unwrap()
        .with_mtls(vec![], RsaKey::none(), Some(vec![cert]))
        // .with_proxy(Proxy::try_from("http: //222.186.129.68:15265").unwrap())
        // .with_mtls(certs, key)
        // .with_proxy(Proxy::new_socks5("127.0.0.1",10279))
        // .with_proxy(Proxy::new_http_plain("127.0.0.1", 10280))
        // .connect("https://104.18.34.137".sni("whatnot.com")).await.unwrap()
        ;
    // let res = req.post("http://127.0.0.1:8000/log", json::object! {"on": false}).await.unwrap();
    // let res = req.get("https://fk1.moutai519.com.cn/bangcle/api/v1/1/1", None).await.unwrap().json().unwrap();
    // let res = req.post("http://127.0.0.1:8000/upload_wac", res).await.unwrap();
    // println!("{}", res.raw_string());
    // let res = req.post("http://127.0.0.1:8000/generate", json::object! {
    //     "ua": "Mozilla/5.0 (Linux; Android 12; 2201123C Build/SKQ1.211006.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/123",
    //     "body":{},
    //     "uid": "5656"
    // }).await.unwrap();
    // println!("{}", res.json().unwrap().pretty());
    // return;
    // req.connect("https://test.gmssl.cn/").await.unwrap();
    let res = req.get("https://test.gmssl.cn/", None).await.unwrap();
    // println!("{}", res.raw_string());


    // let url = "https://www.dickssportinggoods.com/p/2026-topps-flagship-football-mega-box-26topufang4p4ib5vqjhq/26topufang4p4ib5vqjhq";
    // let url = "https://ts3.tc.mm.bing.net/th/id/ODF.dsR0yzVOEBuWxCU9cjAM4Q?w=32&h=32&qlt=96&pcl=fffffa&o=6&pid=1.2";
    // let sid1 = req.send(Method::GET, url, None).await.unwrap();
    // let url = "https://ts3.tc.mm.bing.net/th/id/ODF.pnhuF5msYDWgeLYHsiLTig?w=32&h=32&qlt=95&pcl=fffffa&o=6&pid=1.2";
    // let sid2 = req.send(Method::POST, url, None).await.unwrap();

    // let res1 = req.recv(sid1).await.unwrap();
    // let res1 = req.get(url, None).await.unwrap();
    // println!("{}", res1.raw_string());
    // let res2 = req.recv(sid1).await.unwrap();
    // println!("{}", res2.raw_string());
    // println!("{}", Time::now().as_mills() - t.as_mills())

    // req.set_url("https://shopee.tw/").await.unwrap();
    // req.set_json(data);
    // req.set_auto_redirect(false);
    // req.set_url("http://zwfw.hubei.gov.cn/web/user/uias_login.do?appCode=hbzwfw&gotoUrl=http%3A%2F%2Fzwfw.hubei.gov.cn%2Fwebview%2Fgrkj%2Fwelcome.html&p01=").await.unwrap();
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
    // req.set_url("https://oauth.hubei.gov.cn:8443/").await.unwrap();
    // let res = req.get("https://dns.alidns.com/resolve?name=crypto.cloudflare.com&type=HTTPS", None).await.unwrap();
    // let res=req.get("https://www.link114.cn/",None).await.unwrap();
    // let res = req.get("https://www.bing.com".params(json::object! {}), vec![0u8; 0].ty(Application::Json)).await.unwrap();
    // let res = req.get("https://117.89.181.21".sni("m.sogou.com"), None).await.unwrap();
    // let url = Url::try_from("https://cn.bing.com/").unwrap();
    // let url = "https://113.108.215.122/xhr/front/trade/priority/rushPurchase/hot/branch/one".sni("h5.moutai519.com.cn").unwrap(); //
    // let url: Url = "https://www.bing.com".try_into().unwrap();
    // let url: Url = "https://cn.bing.com".try_into().unwrap();
    // let url = "https://shop.lululemon.com/help/orders/gift-card-balance";


    // println!("{} {}", res1.header(), res2.header());
    // let res = req.get("https://m.sogou.com", None).await.unwrap();
    // let session=req.stream_mut().tls_session().cloned();
    // req.set_tls_session(session);
    // let res = req.get("https://150.139.229.223".sni("h5.moutai519.com.cn"), None).await.unwrap();
    // let res = req.get("https://aswbe.ana.co.jp/webapps/reservation/flight-search", None).await.unwrap();
    // req.re_conn(None).await.unwrap();
    // let res = req.get("https://aswbe.ana.co.jp/webapps/reservation/flight-search", None).await.unwrap();
    // let res = req.send("https://oauth.hubei.gov.cn:8443/", None).await.unwrap();
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