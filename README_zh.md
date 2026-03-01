[![Github](https://github.com/xllgl2017/reqrio/actions/workflows/main.yml/badge.svg)](https://github.com/xllgl2017/reqrio/actions/workflows/main.yml)
[![Apache](https://img.shields.io/badge/license-Apache2.0-blue.svg?logo=apache)](https://github.com/xllgl2017/reqrio/blob/main/LICENSE-APACHE)
[![Crates](https://img.shields.io/crates/v/reqrio.svg?logo=rust&label=rust)](https://crates.io/crates/reqrio)
[![PyPI](https://img.shields.io/pypi/v/reqrio.svg?logo=pypi)](https://pypi.org/project/reqrio/)
[![Npm](https://img.shields.io/npm/v/reqrio.svg?logo=npm)](https://www.npmjs.org/package/reqrio)
[![Maven](https://img.shields.io/maven-central/v/io.github.xllgl2017/reqrio?logo=apachemaven&label=maven)](https://search.maven.org/artifact/io.github.xllgl2017/reqrio)
[![Go](https://img.shields.io/crates/v/reqrio.svg?logo=go&label=go)](https://github.com/xllgl2017/reqrio/tags)

[![Rustdocs](https://docs.rs/reqrio/badge.svg)](https://docs.rs/reqrio)
[![Javadocs](https://javadoc.io/badge/io.github.xllgl2017/reqrio/latest.svg)](https://javadoc.io/doc/io.github.xllgl2017/reqrio/latest)

# reqrio

## 介绍

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;reqrio 是一个旨在快速、轻松且便捷地发送 HTTP 请求的库。
其目标是实现快速、简单便捷的HTTP请求使用。

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Reqrio是一个HTTP请求库，支持多种协议和语言绑定，提供高性能的HTTP客户端功能。

## 特性/亮点

- HTTP协议支持
- 支持HTTP/1.1和HTTP/2（H2）协议
- 同步和异步请求模式
- 请求/响应处理
- Cookie自动继承管理
- 请求标头顺序控制
- 数据流处理

## TLS安全功能

- TLS 1.2支持
- TLS指纹欺骗（JA3/JA4）
- 自定义指纹支持
- 支持多种密码套件

## 代理支持

- HTTP代理
- SOCKS5代理（无身份验证模式）

## 数据处理

- JSON支持
- 多种数据格式（表单、JSON、文本、二进制）
- 压缩支持（Gzip、Deflate、Brotli、Zstd）
- 编码支持（Base64、十六进制、URL编码）

## 语言绑定

- 铁锈（原生）
- Python（FFI）
- Java（JNA）
- Node.js（FFI）
- Qt/C++（FFI）
- Go（CGO）

## 使用示例

### Rust

* 添加依赖
    ```yaml
    [dependencies]
    reqrio = "0.1.1"
    ```

* 示例
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

* 安装
    ```bash
    pip install reqrio
    ```
* 示例
    ```python
  from reqrio import Session, ALPN
  
  session = Session(ALPN.HTTP11)
  resp = session.get("https://httpbin.org/get")
  print(resp.text())
  
    ```

### Java/Maven

* 依赖
    ```xml
    <dependency>
        <groupId>io.github.xllgl2017</groupId>
        <artifactId>reqrio</artifactId>
        <version>0.1.1</version>
    </dependency>
    ```

* 示例

  ```java
  import org.xllgl2017.Session;
  import org.xllgl2017.Response;
  
  Session session = new Session();
  session.setUrl("https://httpbin.org/get");
  Response resp = session.get();
  System.out.println(resp.toString());
  
  ```

### Node.js

* 安装

  ```bach
  npm install reqrio
  ```

* 示例
  ```javascript
  
  const {Session, ALPN} = require('reqrio');
  
  async function main() {
    const session = new Session(ALPN.HTTP11);
    const resp = session.get("https://httpbin.org/get");
    console.log(resp.text());
  }
  ```

### Go

* 示例
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

## WebSocket 支持

```rust
let mut ws = WebSocket::open("wss://echo.websocket.org") ?;
ws.write_frame(WsFrame::new_text(true, "Hello")) ?;
let frame = ws.read_frame() ?;
println!("Received: {:?}", frame);
```

# reqtls

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;reqtls是一个高性能的TLS和加密基础库，专为
reqrio生态系统，提供完整的
加密、签名、证书处理和编码功能。它侧重于安全性、可扩展性和
跨平台支持，使其适用于构建HTTPS客户端、代理服务、证书颁发系统，以及
自定义安全通信协议。

## 加密支持

- 密码加密/解密：AES（CBC、ECB、CTR、GCM、OFB）、DES
- RSA加密/解密：支持PKCS1和PSS填充
- AEAD加密：支持各种AEAD算法

## 哈希支持

- MD5、SHA1、SHA224、SHA256、SHA384、SHA512
- HMAC

## 签名算法

- RSA签名（PKCS1、PSS）
- ECDSA签名（多曲线）

## 证书处理

- X.509证书读取和验证
- 证书链验证
- 自定义证书存储
- CA、服务器和客户端证书生成

## 编码支持

- Base64编码/解码
- URL编码/解码
- 压缩（Gzip、Deflate、Brotli、Zstd）

## 许可证

该项目是Apache 2.0许可证下的开源项目。

## 贡献

欢迎提交问题和拉取请求。

## 联系方式

* Tg：https://t.me/+VVfbAeug-ohhZjU1
* QQ：1083315546