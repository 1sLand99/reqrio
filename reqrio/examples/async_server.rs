use std::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use reqrio::{TlsConfig, TlsStream, ALPN};
use reqtls::{Certificate, RsaKey};

#[tokio::main]
async fn main() {
    let listen = TcpListener::bind("0.0.0.0:7878").await.unwrap();
    let cert = fs::read(r"C:\Users\XLX\Desktop\xnm\1\server.crt").unwrap();
    let mut certificates = Certificate::from_pem(cert).unwrap();
    let key = fs::read(r"C:\Users\XLX\Desktop\xnm\1\server.key").unwrap();
    let pri_key = RsaKey::from_pri_pem(key).unwrap();
    loop {
        let (stream, addr) = listen.accept().await.unwrap();
        println!("Accepted connection from {}", addr);
        let mut tls_stream = TlsStream::accept(stream, TlsConfig {
            sni: "",
            alpn: &ALPN::Http20,
            fingerprint: &mut Default::default(),
            certificate: &mut certificates,
            private_key: &pri_key,
            verify: false,
        }).await;
        if let Ok(mut tls_stream) = tls_stream {
            tokio::spawn(async move {
                tls_stream.write_all("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".as_bytes()).await.unwrap();
                let mut buffer = [0; 1024];
                loop {
                    let len = tls_stream.read(&mut buffer).await.unwrap();
                    if len == 0 { break; }
                    println!("{:?}", &buffer[..len]);
                }
            });
        }
    }
}