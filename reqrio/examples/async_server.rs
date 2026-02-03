use tokio::net::TcpListener;
use reqrio::TlsStream;

#[tokio::main]
async fn main() {
    let listen=TcpListener::bind("0.0.0.0:7878").await.unwrap();
    loop {
        let (stream, addr) = listen.accept().await.unwrap();
        let tls_stream=TlsStream::accept(stream).await.unwrap();
        
        
    }
}