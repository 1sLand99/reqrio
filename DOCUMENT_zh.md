# reqrio中文文档

reqrio是由rust开发并为其他提供ffi绑定的http库，reqrio的设计目标如下:

* 仿真浏览器、TLS层由BoringSSL(和Chromium相同)提供加解密
* 支持指纹替换，通过ja3、ja4、hex(client_hello+client_exchanged_key+change_cipher_spec)
* 低依赖、体积小、快速、高效
* 支持Server、mTls

## 接口文档

不同语言、不同版本有少许差异，可根据IDE补全，下面的示例仅展示rust语言

### AcReq/ScReq - 异步/同步请求；异步需要打开aync features

#### 设置请求地址(set_url)

* 示例

```text
req.set_url("https://www.baidu.com")
```

#### set_alpn - 设置支持HTTP最高版本，默认HTTP/1.1，真实使用的版本需要和服务器协商

* 示例

```text
req.set_alpn(ALPN::HTTP11)
```

#### set_proxy - 设置代理，仅支持http_plain和socks5

* 示例

```text
//无认证httpPlain
req.set_proxy(Proxy::try_from("http://127.0.0.1:5845")
//有认证socks5
req.set_proxy(Proxy::try_from("socks5://username:password@127.0.0.1:5845")
```

#### set_header_json - 设置请求头

* 示例

```text
let headers=json::object!{
    "user-agent":"okhttp/3.13"
}
req.set_header_json(headers)
```

#### insert_header - 添加请求头，添加一个请求头，已存在的会被覆盖

* 示例

```text
req.insert_header("custom","value")
```

#### remove_header - 删除一个请求头，并返回对应值

* 示例

```text
req.remove_header("secret_json")
```

#### set_params - 添加URL请求参数，传入json，传入后自动对值进行url编码

* 示例

```text
let params=json::object!{
    "query":"value",
    "page":1,
    "sort":true
}
req.set_params(params)
```

#### add_param - 添加一个请求参数

* 示例

```text
req.add_param("sign","absc")
```

#### remove_param - 删除一个请求参数

* 示例

```text
req.remove_param("sign")
```

#### set_mtls - 设置mTls连接时所需的证书，ca仅在校验服务器证书/数据时需要

* 示例

```text
let certs=Certificate::from_pem_file("path/to/cert").unwrap();
let key=RsaKey::from_pri_pem_file("path/to/cert/key").unwrap();
req.set_mtls(certs,key,None);
```

#### set_auto_redirect - 设置对需要跳转的链接是否进行自动跳转

* 示例

```text
req.set_auto_redirect(false)//不进行自动跳转
```

#### set_verify - 是否校验服务器证书/数据(生产环境谨慎设置为false)

```text
req.set_verify(false);//不校验
```

#### set_data - 设置请求体，自动设置类型为`application/x-www-form-urlencoded`，传入的值不需要进行编码

* 示例

```text
let data=json::object!{
    "sign":"assb",
    "sort":true,
}
req.set_data(data)
```

#### set_json - 设置请求体，自动设置类型为`application/json`

* 示例

```text
let data=json::object!{
    "sign":"assb",
    "sort":true,
}
req.set_json(data)
```

#### set_text - 设置请求体，自动设置类型为`text/plain`

* 示例

```text
req.set_text("body")
```

#### set_files - 设置上传文件

仅rust语言

* 示例
```text
let data=json::object!{"key":"value"};
let mut file=HttpFile::new_path_data(data,"path/to/file1").unwrap();
file.add_form(FileForm::new_path("path/to/file2").unwrap());
req.set_files(file).unwrap();
```

#### add_file - 添加一个上传文件
仅rust语言

* 示例
```text
req.add_file("path/to/file1").unwrap();
```

#### set_bytes - 设置请求体，需要手动设置请求体类型

* 示例

```text
req.set_bytes(b"body")
```

### Fingerprint - 指纹数据(仅付费用户)

非rust语言的session有提供对的接口

#### set_ja3 - 使用ja3设置tls指纹数据，需要token

```text
finger.set_ja3("<ja3>", "<token>");
```

#### set_ja4 - 使用ja4设置tls指纹数据，需要token

```text
finger.set_ja4("<ja4>", "<token>");
```

#### from_hex_all - 使用握手十六进制数据，需要token

包括client_hello+client_exchanged_key+change_cipher_spec

* 示例

```text
Fingerprint::from_hex_all("<hex(client_hello+client_exchanged_key+change_cipher_spec)>","<token>")
```

#### random - 使用随机指纹

其他语言在构建session时有对应的参数

* 示例

```text
Fingerprint::random("<token>")
```