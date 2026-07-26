use reqrio::*;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::path::Path;

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
    let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(23, 214, 95, 199), 443));
    let config = ClientConfig {
        sni: "img-s-msn-com.akamaized.net",
        alpn: &ALPN::Http30,
        fingerprint: &mut TlsFinger::Default,
        client_cert: &mut vec![],
        cert_key: &RsaKey::none(),
        verify: false,
        ca_certs: &[],
        key_log: Some(Path::new("2.log").to_path_buf()),
        session: &None,
    };
    let _stream = QUICStreamS::connect(socket, addr, config).unwrap();
}