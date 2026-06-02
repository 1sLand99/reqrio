# 📦 reqrio — 轻量、高性能、指纹级 HTTP 请求库

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`reqrio` 是一个面向高性能与浏览器级行为模拟设计的 HTTP 请求库，主要用于需要精确控制网络行为的场景，
比如协议研究、指纹分析、高并发采集以及复杂反爬环境下的请求构造。它并不是传统意义上追求"简单易用"的 HTTP 客户端，而是更偏向底层请求行为的可控
性与一致性，让开发者能够尽可能贴近真实浏览器的网络栈行为，包括 **TLS 握手特征**、**HTTP/2 行为**以及 **Header 排列方式**等。

> ⚡ **适用场景**：协议研究 | 反爬绕过 | 指纹控制 | 高并发系统

---

## ✨ 核心特性

| 类别            | 能力                                                                                              |
|---------------|-------------------------------------------------------------------------------------------------|
| **协议支持**      | HTTP/1.1 & HTTP/2 (H2)                                                                          |
| **请求模式**      | 同步 & 异步                                                                                         |
| **TLS 指纹**    | JA3、JA4、原始十六进制 ClientHello、随机指纹                                                                 |
| **密码套件**      | 多种套件，基于 [reqtls](https://github.com/xllgl2017/reqrio/tree/master/reqtls#tls-record-layer-tls12) |
| **请求头控制**     | 有序请求头，与浏览器一致的[排序表](https://github.com/xllgl2017/reqrio/blob/main/HEADER.md)                     |
| **Cookie 管理** | 自动继承与会话维持                                                                                       |
| **流式处理**      | 低拷贝数据管道，极致内存效率                                                                                  |
| **代理支持**      | HTTP 代理 & SOCKS5 代理                                                                             |
| **压缩支持**      | Gzip、Deflate、Brotli、Zstd                                                                        |
| **编码支持**      | Base64、Hex、URL 编码                                                                               |

---

## 🌊 流式请求与解析（低拷贝架构）

`reqrio` 是一个 **低拷贝（low-copy）** 请求发送引擎，用于高效地将用户数据或文件数据通过 TLS 加密后发送到 TCP。

在 **发送** 时，对用户传入的 form-data、JSON、text 等数据转为 bytes 储存，仅在进入 TLS 加密阶段发生 **一次 copy**，其余阶段仅对数据进行
`borrow`（借用）；文件上传则通过 `into_reader` 读取，减小内存开销。

在 **接收** 时，直接将解密后的数据写入引擎层的 buffer，由引擎层解压解析后返回给用户。

```text
┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ Write ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐
│                ┌────────┐               ┌──────────┐             ┌──────────┐                 │
│       Url,Body │ ScReq  │ encode->bytes │  Request │ copy slice  │ fragment │ write ┌───────┐ │
│ User ─────────►│ AcReq  │──────────────►│  borrow  │────────────►│   TLS    │──────►│  TCP  │ │
│                │(Engine)│  into_reader  │  reader  │             │ Encrypt  │       └───────┘ │
│                └────────┘               └──────────┘             └──────────┘                 │
└ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘
┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─  Read ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─  ─ ─ ─ ─ ┐
│                 ┌──────────┐            ┌────────┐                 │
│ ┌───────┐ read  │   TLS    │ decrypt to │ ScReq  │  return         │
│ │  TCP  │──────►│ Fragment │───────────►│ AcReq  │─────────► User  │
│ └───────┘       │ Decrypt  │            │(Engine)│ Response        │
│                 └──────────┘            └────────┘                 │
└ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─┘

```

---

## 🔐 TLS 安全与指纹（**仅订阅**）

### 支持功能

- **TLS 1.2**，真实浏览器指纹模拟
- **JA3 / JA4** 指纹设置
- ClientHello 指纹
- **自定义** 指纹
- **随机指纹** 

### 设置 TLS 指纹

**自定义 TLS（十六进制格式）：**

```text
fingerprint = {
    "sec_ch_ua": "\"Microsoft Edge\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
    "sec_ch_ua_mobile": "?0",
    "sec_ch_ua_platform": "\"Linux\"",
    "tls_finger": "hex(client_hello)",
    "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 ..."
}
client_hello=hex_decode(fingerprint["tls_finger"].to_string())?;
req.set_fingerprint(Fingerprint::from_client_hello(client_hello, "<token>")
fingerprint.remove("tls_finger")
headers.update(fingerprint)
req.set_headers(headers)
```

**JA3：**

```text
req.set_ja3("<ja3>", "<token>");
```

**JA4：**

```text
req.set_ja4("<ja4>", "<token>");
```

---

## 🌐 多语言绑定

| 语言               | 包管理                                                                           | 文档                                                                  |
|------------------|-------------------------------------------------------------------------------|---------------------------------------------------------------------|
| **Rust**（原生）     | [crates.io](https://crates.io/crates/reqrio)                                  | [docs.rs](https://docs.rs/reqrio)                                   |
| **Python**（FFI）  | [PyPI](https://pypi.org/project/reqrio/)                                      | —                                                                   |
| **Java**（JNA）    | [Maven Central](https://search.maven.org/artifact/io.github.xllgl2017/reqrio) | [Javadoc](https://javadoc.io/doc/io.github.xllgl2017/reqrio/latest) |
| **Node.js**（FFI） | [npm](https://www.npmjs.org/package/reqrio)                                   | —                                                                   |
| **Go**（CGO）      | [pkg.go.dev](https://pkg.go.dev/github.com/xllgl2017/reqrio/reqrio-go)        | —                                                                   |
| **Qt/C++**（FFI）  | —                                                                             | —                                                                   |

---

## 🚀 快速开始

### 初始化 Session

```rust
use reqrio::*;
fn ff() {
    let headers = json::object! {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "Cookie": "__guid=15015764.1071255116101212729.1764940193317.2156; env_webp=1; _S=pvc5q7leemba50e4kn4qis4b95; QiHooGUID=4C8051464B2D97668E3B21198B9CA207.1766289287750; count=1; so-like-red=2; webp=1; so_huid=114r0SZFiQcJKtA38GZgwZg%2Fdit1cjUGuRcsIL2jTn4%2FE%3D; __huid=114r0SZFiQcJKtA38GZgwZg%2Fdit1cjUGuRcsIL2jTn4%2FE%3D; gtHuid=1",
        "Pragma": "no-cache",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": 1,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0",
        "sec-ch-ua": r#""Microsoft Edge";v="143", "Chromium";v="143", "Not A(Brand";v="24""#,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": r#""Windows""#
    };
    let mut req = ScReq::new()
        // 设置最高 HTTP 版本，默认 HTTP/1.1
        .with_alpn(ALPN::Http20)
        // Session 内部默认不设置任何请求头，需要手动设置
        .with_header_json(headers).unwrap()
        // 设置请求超时和尝试请求次数
        .with_timeout(Timeout::new_same(3000, 3));
}
```

### GET 请求示例

```rust
use reqrio::*;

fn ff() {
    let mut req = ScReq::new();
    // GET 请求
    let mut res = req.get("https://www.baidu.com", None).unwrap();
    // 获取响应头
    let header = res.header();
    // 获取响应体（不转移所有权）
    let body = res.decode_body().unwrap();
    // 获取 JSON（转移所有权）
    let json = res.json().unwrap();
}
```

### 表单提交

```rust
use reqrio::*;
fn ff() {
    let mut req = ScReq::new();
    let url = "https://www.baidu.com/api";
    let data = json::object! {
        "field1":"value1",
        "field2":"value2"
    };
    let resp = req.post(url, data.form()).unwrap();
}
```

### JSON 提交

```rust
use reqrio::*;
fn ff() {
    let mut req = ScReq::new();
    let url = "https://www.baidu.com/api";
    let data = json::object! {
        "field1":"value1",
        "field2":"value2"
    };
    let resp = req.post(url, data).unwrap();
}
```

### 提交实现了 `Serialize` 的结构体

> 需要添加 `serde` 特性

```rust
use reqrio::*;
use serde::Serialize;
fn ff() {
    let mut req = ScReq::new();
    #[derive(Serialize)]
    struct Data {
        field1: String,
        field2: bool
    }
    let url = "https://www.baidu.com/api";
    let resp = req.post(url, Body::json(&Data { field1: "value".to_string(), field2: false }).unwrap()).unwrap();
}
```

---

## 🔌 WebSocket 支持

```rust
let mut ws = WebSocket::open("wss://echo.websocket.org") ?;
ws.write_frame(WsFrame::new_text(true, "Hello")) ?;
let frame = ws.read_frame() ?;
println!("Received: {:?}", frame);
```

---

## 📄 许可证

本项目基于 **Apache 2.0 License** 开源 —
详见 [LICENSE-APACHE](https://github.com/xllgl2017/reqrio/blob/main/LICENSE-APACHE) 文件。

---

## 🤝 贡献指南

欢迎提交 Issue 和 Pull Request！

---

## 📬 联系方式

- **Telegram**：[https://t.me/+VVfbAeug-ohhZjU1](https://t.me/+VVfbAeug-ohhZjU1)
- **QQ**：1083315546
