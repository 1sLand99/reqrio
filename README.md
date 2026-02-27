[<img alt="github" src="https://img.shields.io/badge/github-reqrio-8da0cb?logo=github" height="20">](https://github.com/xllgl2017/reqrio)
[![Apache](https://img.shields.io/badge/license-Apache2.0-blue.svg?logo=apache)](https://github.com/xllgl2017/reqrio/blob/main/LICENSE-APACHE)
[![Crates](https://img.shields.io/crates/v/reqrio.svg?logo=rust&label=rust)](https://crates.io/crates/reqrio)
[![PyPI](https://img.shields.io/pypi/v/reqrio.svg?logo=pypi)](https://pypi.org/project/reqrio/)
[![Npm](https://img.shields.io/npm/v/reqrio.svg?logo=npm)](https://www.npmjs.org/package/reqrio)
[![Maven](https://img.shields.io/maven-central/v/io.github.xllgl2017/reqrio?logo=apachemaven&label=maven)](https://search.maven.org/artifact/io.github.xllgl2017/reqrio)
[![Go](https://img.shields.io/crates/v/reqrio.svg?logo=go&label=go)](https://github.com/xllgl2017/reqrio/tags)

[![Rustdocs](https://docs.rs/reqrio/badge.svg)](https://docs.rs/reqrio)
[![Javadocs](https://javadoc.io/badge/io.github.xllgl2017/reqrio/latest.svg)](https://javadoc.io/doc/io.github.xllgl2017/reqrio/latest)

# reqrio

## Introduction

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;reqrio is a library designed for making HTTP requests quickly, easily, and conveniently.
Its goal is to enable fast,
simple, and convenient use of HTTP requests.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Reqrio is an HTTP request library that supports multiple protocols and language bindings,
providing high-performance
HTTP client capabilities.

## Features

- HTTP protocol support
- Support for HTTP/1.1 and HTTP/2 (H2) protocols
- Synchronous and asynchronous request modes
- Request/Response Handling
- Cookie Automatic Inheritance Management
- Request Header Order Control
- Data stream processing

## TLS Security Features

- TLS 1.2 Support
- TLS Fingerprint Spoofing (JA3/JA4)
- Custom fingerprint support
- Support for multiple cipher suites

## Proxy Support

- HTTP Proxy
- SOCKS5 Proxy (No Authentication Mode)

## Data Processing

- JSON support
- Multiple data formats (forms, JSON, text, binary)
- Compression support (Gzip, Deflate, Brotli, Zstd)
- Encoding Support (Base64, Hex, URL Encoding)

## Language Bindings

- Rust (Native)
- Python (FFI)
- Java (JNA )
- Node.js (FFI )
- Qt/C++ (FFI )
- Go (CGO)

## Usage

### Rust

* dependency
    ```yaml
    [dependencies]
    reqrio = "0.1.1"
    ```

* Example
    ```rust
    use reqrio::ScReq;
    
    fn main() -> Result<(), Box<dyn std::error::Error>> {
        let resp = ScReq::new()
            .with_url("https://httpbin.org/get")?
            .send_check(reqrio::Method::Get)?;
        println!("Status: {}", resp.header().status().code());
        println!("Body: {}", resp.text()?);
        Ok(())
    }
    ```

### Python

* Install
    ```bash
    pip install reqrio
    ```
* Example
    ```python
  from reqrio import Session, ALPN
  
  session = Session(ALPN.HTTP11)
  resp = session.get("https://httpbin.org/get")
  print(resp.text())
  
    ```

### Java/Maven

* dependency
    ```xml
    <dependency>
        <groupId>io.github.xllgl2017</groupId>
        <artifactId>reqrio</artifactId>
        <version>0.1.1</version>
    </dependency>
    ```

* Example

  ```java
  import org.xllgl2017.Session;
  import org.xllgl2017.Response;
  
  Session session = new Session();
  session.setUrl("https://httpbin.org/get");
  Response resp = session.get();
  System.out.println(resp.toString());
  
  ```

### Node.js

* Install

  ```bach
  npm install reqrio
  ```

* Example
  ```javascript
  
  const {Session, ALPN} = require('reqrio');
  
  async function main() {
    const session = new Session(ALPN.HTTP11);
    const resp = session.get("https://httpbin.org/get");
    console.log(resp.text());
  }
  ```

### Go

* Example
  ```go
  import("github.com/xllgl2017/reqrio/reqrio-go/reqrio")
  
  session := reqrio.NewSession()
  err := session.SetUrl("https://m.so.com")
  if err != nil {
    return
  }
  resp, err := session.Get()
  if err != nil {
    return
  }
  println(resp.Text())
  
  ```

## WebSocket Support

```rust
let mut ws = WebSocket::open("wss://echo.websocket.org") ?;
ws.write_frame(WsFrame::new_text(true, "Hello")) ?;
let frame = ws.read_frame() ?;
println!("Received: {:?}", frame);
```

# reqtls

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;reqtls is a high-performance TLS and cryptographic foundation library built for the
reqrio ecosystem, providing complete
encryption, signing, certificate handling, and encoding capabilities. It focuses on security, scalability, and
cross-platform support, making it suitable for building HTTPS clients, proxy services, certificate issuance systems, and
custom secure communication protocols.

## Encryption support

- Cipher Encryption/Decryption: AES (CBC, ECB, CTR, GCM, OFB), DES
- RSA Encryption/Decryption: Supports PKCS1 and PSS padding
- AEAD Encryption: Supports various AEAD algorithms

## Hash support

- MD5, SHA1, SHA224, SHA256, SHA384, SHA512
- HMAC

## Signature Algorithm

- RSA Signature (PKCS1, PSS)
- ECDSA Signature (Multiple Curves)

## Certificate Processing

- X.509 Certificate Reading and Verification
- Certificate chain verification
- Custom Certificate Store
- CA, Server, and Client certificate generation

## Encoding Support

- Base64 Encoding/Decoding
- URL Encoding/Decoding
- Compression (Gzip, Deflate, Brotli, Zstd)

## License

This project is open source under the Apache 2.0 License.

## Contributing

Welcome to submit Issues and Pull Requests.

## Contact

* Tg: https://t.me/+VVfbAeug-ohhZjU1
* QQ: 1083315546