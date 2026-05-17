# 📦 reqrio - 一个轻量、高性能、指纹级的HTTP 请求库

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`reqrio` 是一个面向高性能与浏览器级行为模拟设计的HTTP请求库，主要用于需要精确控制网络行为的场景，
比如协议研究、指纹分析、高并发采集以及复杂反爬环境下的请求构造。 它并不是传统意义上追求“简单易用”的HTTP客户端，而是更偏向底层请求行为的可控
性与一致性，让开发者能够尽可能贴近真实浏览器的网络栈行为，包括 TLS 握手特征、HTTP/2 行为以及 Header 排列方式等。

✨ 一下是`reqrio`的特色：

* 高并发与低内存开销
* 流式数据处理
* 为协议研究 / 反爬 / 指纹控制提供基础能力
* 支持TLS指纹，可以通过TLS握手的十六进制、ja3、ja4设置(**仅订阅**),
* **有序请求头**(查看[请求头顺序表](https://github.com/xllgl2017/reqrio/blob/main/HEADER.md))，和浏览器一致
* [**BoringSSL**](https://github.com/google/boringssl)提供加解密/密码学算法。

## 🌊 流式请求和解析

`reqrio` 是一个 低拷贝（low-copy）请求发送引擎，用于高效地将 用户数据或文件数据 通过 TLS 加密后发送到 TCP。`reqrio`在发送时，
对用户传入form-data、json、text等数据进行转bytes储存，然后仅在进入 TLS 加密阶段时发生一次 copy， 其余阶段仅对数据进行
borrow（借用），对文件上传则通过into_reader进行读取，减小内存开销；在接收时，直接将解密后的数据直接写入引擎层的buffer，
然后由引擎层进行解压解析后返回到用户

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


## 🚀 快速开始

* 初始化Session

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
        //设置最高HTTP版本，默认HTTP/1.1
        .with_alpn(ALPN::Http20)
        //Session内部默认不设置任何请求头，需要手动设置
        .with_header_json(headers).unwrap()
        //设置请求超时和尝试请求次数
        .with_timeout(Timeout::new_same(3000, 3));
}
```

* GET的简单示例

```rust
use reqrio::*;

fn ff() {
    let mut req = ScReq::new();
    //get
    let mut res = req.get("https://www.baidu.com", None).unwrap();
    //获取相应头
    let header = res.header();
    //获取相应体，不移动所有权
    let body = res.decode_body().unwrap();
    //获取json，转移所有权
    let json = res.json().unwrap();
}
```

* 表单提交示例

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

* json提交示例

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

* 提交已实现`Serialize`的struct示例

* 需要添加serde特性

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


