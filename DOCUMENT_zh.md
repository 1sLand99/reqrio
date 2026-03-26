from reqrio import Session

# reqrio中文

## Rust API文档

### AcReq/ScReq - 异步/同步请求；异步需要打开aync features

#### 设置请求地址(set_url)

在0.1-0.2版本中set_url，应在设置请求体之前，否则请求体会被清除

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

认证模式中，username，password支持url编码

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

**注意**: 这里的value应该是未进行url_encode的原始值

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

## Python API文档

### Session - 请求会话

#### 初始化Session

在初始化session可以设置;

1. rand_tls: 是否使用随机指纹，默认False
2. token: rand_tls为True是需要
3. verify: 是否校验服务器下发的数据、证书
4. alpn: 设置最大握手HTTP版本，默认HTTP/1.1；实际交版本是和服务器协商的结果

* 示例
  ```python
  session = Session(alpn=ALPN.HTTP20, rand_tls=True, token="<token>")
  ```

#### 设置请求地址(set_url)

在0.1-0.2版本中set_url，应在设置请求体之前，否则请求体会被清除

* 示例

  ```python
  session.set_url("https://www.baidu.com")
  ```

#### set_proxy - 设置代理，仅支持http_plain和socks5

认证模式中，username，password支持url编码

* 示例

  ```python
  # 无认证httpPlain示例
  session.set_proxy("http://127.0.0.1:5845")
  # 有认证socks5示例
  session.set_proxy("socks5://username:password@127.0.0.1:5845")
  ```

#### set_headers - 设置请求头

* 示例

  ```python
  headers = {
      "user-agent": "okhttp/3.13"
  }
  session.set_headers(headers)
  ```

#### add_header - 添加请求头，添加一个请求头，已存在的会被覆盖

* 示例

  ```text
  session.add_header()("custom","value")
  ```

#### set_params - 添加URL请求参数，传入dict

**注意**: 这里的value应该是未进行url_encode的原始值

* 示例

  ```text
  params={
      "query":"value",
      "page":1,
      "sort":true
  }
  session.set_params(params)
  ```

#### add_param - 添加一个请求参数

**注意**: 这里的value应该是未进行url_encode的原始值

* 示例

  ```text
  session.add_param("sign","absc")
  ```

#### set_context_type - 使用握手十六进制数据，需要token

仅在set_bytes时需要, 其他有默认值:

1. set_data: application/x-www-form-urlencoded

2. set_text: text/plain

3. set_json: application/json

* 示例:

  ```text
  session.set_context_type("application/json")
  ```

#### set_data - 设置x-www-form-urlencoded的请求体

* 示例:
  ```python
  data={
    'name':'value',
    'name1':1,# 这里支持数值
    'name2':True,# 支持bool
    'name3':{'n':'v'},# 支持dict，自动转json
  }
  session.set_data(data)
  ```

#### set_json - 设置json的请求体

* 示例:
  ```python
  json={
    'name':'value'
  }
  session.set_json(json)
  ```

#### set_text - 设置text请求体

* 示例:
  ```python
  session.set_text('body')
  ```

#### set_timeout - 设置超时(毫秒)

connect: 建立tls连接超时

read: 每次tcp读取的超时

write: 每次tcp写出超时

handle: 处理http请求超时

handle_times: 尝试处理http请求的次数，默认3次

connect_times: 尝试建立tls的次数，默认3次

* 示例:
  ```python
  # 将失败重做次数设置1次，即遇到错误时不进行重试
  session.set_timeout(handle_times=1, connect_times=1)
  ```

#### set_ja3 - 使用ja3设置tls指纹数据，需要token

* 示例:
  ```python
  session.set_ja3("<ja3>", "<token>");
  ```

#### set_ja4 - 使用ja4设置tls指纹数据，需要token

* 示例:
  ```python
  session.set_ja4("<ja4>", "<token>");
  ```

#### set_fingerprint - 使用握手十六进制数据，需要token

包括client_hello+client_exchanged_key+change_cipher_spec

* 示例

  ```python
  session.set_fingerprint("<hex(client_hello+client_exchanged_key+change_cipher_spec)>","<token>")
  ```

