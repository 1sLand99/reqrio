use reqrio::*;
use std::collections::HashMap;
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
    let mut h3_req =HTTP3StreamS::connect(ConnParam{
        url: &"https://img-s-msn-com.akamaized.net".try_into().unwrap(),
        proxy: &Proxy::Null,
        timeout: &Default::default(),
        fingerprint: &mut Default::default(),
        alpn: &ALPN::Http30,
        verify: false,
        cert: &mut vec![],
        key: &RsaKey::none(),
        ca_cert: &vec![],
        key_log: &Some(PathBuf::from("2.log")),
        ech: false,
        session: &None,
    }).unwrap();
    let mut resps =HashMap::new();
    loop {
        h3_req.recv(&mut resps).unwrap();
    }
}