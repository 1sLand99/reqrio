use std::collections::HashMap;
use reqrio::*;
use std::fs;
use std::path::PathBuf;

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
fn main() {
    #[cfg(feature = "log")]
    test_log();
    Buffer::check_subscription(fs::read_to_string("TOKEN").unwrap()).unwrap();
    let url = "https://img-s-msn-com.akamaized.net".try_into().unwrap();
    let mut fingerprint = Fingerprint::default();
    let mut h3_req = HTTP3StreamS::connect(ConnParam {
        url: &url,
        proxy: &Proxy::Null,
        timeout: &Default::default(),
        fingerprint: &mut fingerprint,
        alpn: &ALPN::Http30,
        verify: false,
        cert: &mut vec![],
        key: &RsaKey::none(),
        ca_cert: &vec![],
        key_log: &Some(PathBuf::from("2.log")),
        ech: false,
        session: &None,
    }).unwrap();
    let mut header = Header::new_req_h3();

    header.set_by_json(json::object! {
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
    }).unwrap();
    let body: Body = None.into();
    let sid = h3_req.send(&url, &mut header, &body, &fingerprint).unwrap();
    let mut resps = HashMap::new();
    resps.insert(sid, Response::new());
    let resp = loop {
        let mut sids = h3_req.recv(&mut resps).unwrap();
        if sids.len() > 0 { break resps.remove(&sids.remove(0)); }
    }.unwrap();
    println!("{}", resp.raw_string())
}