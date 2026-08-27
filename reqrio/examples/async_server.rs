use reqrio::TlsStream;
use reqtls::{Certificate, RsaKey, ServerConfig, ALPN};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;

#[tokio::main]
async fn main() {
    let listen = TcpListener::bind("0.0.0.0:7878").unwrap();
    let cert = fs::read(r"C:\Users\XLX\Desktop\xnm\1\server.crt").unwrap();
    let mut certificates = Certificate::from_pem(cert).unwrap();
    let key = fs::read(r"C:\Users\XLX\Desktop\xnm\1\server.key").unwrap();
    let pri_key = RsaKey::from_pri_pem(key).unwrap();
    loop {
        let (stream, addr) = listen.accept().unwrap();
        println!("Accepted connection from {}", addr);
        let tls_stream = TlsStream::accept(stream, ServerConfig {
            alpn: &ALPN::Http20,
            ca: &mut Certificate::none(),
            server_cert: &mut certificates,
            cert_key: &pri_key,
            verify: false,
            ca_certs: &vec![],
            key_log: None,
        }).wait();
        if let Ok(mut tls_stream) = tls_stream {
            tokio::spawn(async move {
                let mut buffer = [0; 1024];
                loop {
                    let len = tls_stream.read(&mut buffer).unwrap();
                    if len == 0 { break; }
                    println!("{}", String::from_utf8_lossy(&buffer[..len]));
                    if buffer.starts_with(b"GET") || buffer.starts_with(b"POST") {
                        tls_stream.write_all("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".as_bytes()).unwrap();

                    }
                }
            });
        }
    }
}