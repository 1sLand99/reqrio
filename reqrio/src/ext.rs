use crate::body::{BodyType, HttpField};
use crate::error::HlsResult;
use crate::file::HttpFile;
use crate::packet::*;
use crate::timeout::Timeout;
use crate::*;
use json::JsonValue;
use crate::hpack::HackDecode;
use crate::stream::Stream;

pub(crate) struct ReqParam<'a> {
    pub(crate) header: &'a mut Header,
    pub(crate) body: &'a BodyType,
    pub(crate) addr: &'a Addr,
    pub(crate) buffer: &'a mut Buffer,
}

#[allow(private_bounds)]
pub trait ReqExt: ReqPriExt + Sized {
    fn set_data(&mut self, data: JsonValue) {
        let data = data.into_entries().map(|(k, v)| format!("{}={}", k, coder::url_encode(v.dump()))).collect::<Vec<_>>().join("&");
        self.set_bytes(data, ContentType::Application(Application::XWwwFormUrlencoded));
    }
    fn set_text(&mut self, text: impl ToString) {
        self.set_bytes(text.to_string(), ContentType::Text(Text::Plain));
    }
    fn set_json(&mut self, data: JsonValue) {
        self.set_bytes(data.dump(), ContentType::Application(Application::Json));
    }
    fn set_bytes(&mut self, bs: impl Into<Vec<u8>>, ct: ContentType) {
        *self.body_type_mut() = BodyType::Bytes(bs.into());
        self.header_mut().set_content_type(ct);
    }
    /// * 文件上传示例
    /// ```rust
    /// let files=vec![]
    /// files.push(HttpFile::new_fp("path/to/file1"));
    /// files.push(HttpFile::new_fp("path/to/file1"));
    /// let data=json::object!{"key":"value"};
    /// req.set_files(data,files)
    /// ```
    fn set_files(&mut self, data: JsonValue, files: Vec<HttpFile>) -> HlsResult<()> {
        let md5 = hash::md5_hex(data.dump())?;
        let data = data.into_entries().map(|(name, value)| HttpField {
            name,
            value: value.dump(),
        }).collect::<Vec<_>>();
        *self.body_type_mut() = BodyType::Files { data, files };
        self.header_mut().set_content_type(ContentType::File(md5));
        Ok(())
    }
    fn add_file(&mut self, file: HttpFile) {
        if let BodyType::Files { files, .. } = self.body_type_mut() {
            files.push(file);
        } else {
            *self.body_type_mut() = BodyType::Files { data: vec![], files: vec![file] };
        }
        self.header_mut().set_content_type(ContentType::File("".to_string()))
    }
    fn header_mut(&mut self) -> &mut Header;
    fn header(&self) -> &Header;
    fn with_timeout(mut self, timeout: Timeout) -> Self {
        self.set_timeout(timeout);
        self
    }
    fn set_timeout(&mut self, timeout: Timeout);
    fn timeout(&self) -> &Timeout;
    fn timeout_mut(&mut self) -> &mut Timeout;
    fn url(&self) -> String;
    fn set_uri(&mut self, uri: impl TryInto<Uri>) -> Result<(), RlsError> {
        self.header_mut().set_uri(uri.try_into().or(Err(UrlError::ParseUriError))?);
        Ok(())
    }
    fn set_proxy(&mut self, proxy: Proxy);
    fn with_proxy(mut self, proxy: Proxy) -> Self {
        self.set_proxy(proxy);
        self
    }

    ///是否校验服务器下发的消息（证书、签名等），默认校验
    fn set_verify(&mut self, verify: bool);
    fn with_verify(mut self, verify: bool) -> Self {
        self.set_verify(verify);
        self
    }

    ///是否自动进行跳转
    fn set_auto_redirect(&mut self, auto_redirect: bool);
    fn with_auto_redirect(mut self, auto_redirect: bool) -> Self {
        self.set_auto_redirect(auto_redirect);
        self
    }

    /// * 必须在建立tls连接（即：set_url/with_url）前设置, 否则需要调re_conn
    /// * 默认使用http2.0去连接，实际使用协议需要和服务器协商
    fn set_alpn(&mut self, alpn: ALPN) {
        self.header_mut().init_by_alpn(alpn);
    }
    fn with_alpn(mut self, alpn: ALPN) -> Self {
        self.set_alpn(alpn);
        self
    }

    ///启用mtls，并传入客户端证书
    fn set_mtls(&mut self, certs: Vec<Certificate>, key: RsaKey);
    fn with_mtls(mut self, certs: Vec<Certificate>, key: RsaKey) -> Self {
        self.set_mtls(certs, key);
        self
    }

    fn set_callback(&mut self, callback: impl FnMut(&[u8]) -> HlsResult<()> + 'static);
    fn set_fingerprint(&mut self, fingerprint: Fingerprint);
    fn with_fingerprint(mut self, fingerprint: Fingerprint) -> Self {
        self.set_fingerprint(fingerprint);
        self
    }
    fn set_headers(&mut self, mut headers: Header, keep_cookie: bool) {
        if keep_cookie {
            let cks = self.header_mut().cookies().unwrap_or(&vec![]).clone();
            headers.set_cookies(cks);
        }
        *self.header_mut() = headers;
    }

    fn set_headers_json(&mut self, headers: JsonValue) -> HlsResult<()> {
        self.header_mut().set_by_json(headers)
    }

    fn with_header_json(mut self, data: JsonValue) -> HlsResult<Self> {
        self.set_headers_json(data)?;
        Ok(self)
    }

    fn insert_header(&mut self, k: impl AsRef<str>, v: impl ToString) -> HlsResult<()> {
        self.header_mut().insert(k, v)
    }

    fn remove_header(&mut self, k: impl AsRef<str>) -> Option<HeaderValue> {
        self.header_mut().remove(k)
    }

    fn set_params(&mut self, params: JsonValue) {
        let uri = self.header_mut().uri_mut();
        uri.clear_params();
        for (k, v) in params.entries() {
            uri.insert_param(k, v);
        }
    }

    fn add_param(&mut self, name: impl ToString, value: impl ToString) {
        let uri = self.header_mut().uri_mut();
        uri.insert_param(name, value);
    }

    fn remove_param(&mut self, name: impl ToString) -> Option<String> {
        let uri = self.header_mut().uri_mut();
        uri.remove_param(name)
    }
}


pub(crate) trait ReqPriExt {
    fn into_stream(self) -> Stream;
    fn callback(&mut self) -> &mut Option<ReqCallback>;
    fn hack_decoder(&mut self) -> &mut HackDecode;
    fn addr(&self) -> &Addr;
    fn scheme(&self) -> &Scheme;
    fn req_param(&mut self) -> ReqParam<'_>;
    fn body_type(&self) -> &BodyType;
    fn body_type_mut(&mut self) -> &mut BodyType;
    fn handle_h1_res(&mut self, buffer: &mut Buffer, response: &mut Response, rd: &mut usize) -> HlsResult<bool> {
        match self.callback() {
            None => response.extend_buffer(buffer),
            Some(callback) => {
                if response.header().is_empty() {
                    response.extend_buffer(buffer)?;
                    if !response.header().is_empty() {
                        callback(response.raw_body())?;
                        *rd += response.raw_body().len();
                        response.clear_raw();
                    }
                } else {
                    callback(buffer.filled())?;
                    *rd += buffer.filled().len();
                }
                if response.header().is_empty() { return Ok(false); }
                let finish = match response.header().content_length() {
                    None => buffer.filled().ends_with(&[48, 13, 10, 13, 10]),
                    Some(len) => *rd >= len
                };
                buffer.reset();
                Ok(finish)
            }
        }
    }

    fn handle_h2_res(&mut self, frame: H2Frame, response: &mut Response) -> HlsResult<bool> {
        if frame.frame_type() == &FrameType::Goaway { return Err("Connection reset by peer".into()); }
        match self.callback() {
            None => response.extend_frame(frame, self.hack_decoder()),
            Some(callback) => {
                match frame.frame_type() {
                    FrameType::Data => {
                        callback(frame.payload())?;
                        Ok(frame.is_end_frame())
                    }
                    FrameType::Headers => Ok(response.extend_frame(frame, self.hack_decoder())?),
                    _ => Ok(false),
                }
            }
        }
    }

    fn format_file_body(data: &Vec<HttpField>, files: &Vec<HttpFile>, md5: &str) -> HlsResult<Vec<u8>> {
        let mut body = vec![];
        for datum in data {
            body.push(format!("--{}", md5));
            body.push(format!("Content-Disposition: form-data; name=\"{}\"", datum.name));
            body.push("".to_string());
            body.push(datum.value.to_string());
            body.push("".to_string());
        };
        let mut body = body.join("\r\n").into_bytes();
        for file in files {
            body.extend(format!("--{}\r\nContent-Disposition: form-data; name=\"{}\"; filename=\"{}\"\r\n", md5, file.filed_name(), file.filename()).into_bytes());
            if file.file_type() != "" {
                body.extend(format!("Content-Type: {}\r\n", file.file_type()).into_bytes());
            }
            body.extend_from_slice(b"\r\n");
            body.extend(file.raw_bytes());
            body.append(&mut "\r\n".as_bytes().to_vec());
        }
        body.append(&mut format!("--{}--\r\n", md5).as_bytes().to_vec());
        Ok(body)
    }

    fn update_cookie(&mut self, response: &Response) {
        for cookie in response.header().cookies().unwrap_or(&vec![]) {
            if cookie.name() == "" && cookie.value() == "" { continue; }
            self.req_param().header.add_cookie(cookie.clone());
        }
    }

    fn check_status(&self, response: &Response) -> HlsResult<()> {
        let status = response.header().status();
        match status.code() {
            400..600 => Err(format!("网络请求错误-{}", status).into()),
            _ => Ok(())
        }
    }

    fn check_res(&self, response: Response, k: impl AsRef<str>, v: impl ToString, e: Vec<impl AsRef<str>>) -> HlsResult<JsonValue> {
        let data = response.json()?;
        if data[k.as_ref()].to_string() != v.to_string() {
            for e in e {
                if !data[e.as_ref()].is_null() { return Err(data[e.as_ref()].to_string().into()); }
            }
            Err(format!("check fail: key: {}; value: {}", k.as_ref(), v.to_string()).into())
        } else { Ok(data) }
    }
}

#[allow(private_bounds)]
pub trait ReqGenExt: ReqExt {
    fn format_body(&mut self, md5: &str) -> HlsResult<Vec<u8>> {
        match self.body_type() {
            BodyType::Bytes(bytes) => Ok(bytes.to_vec()),
            BodyType::Files { data, files } => {
                let body_bytes = Self::format_file_body(data, files, md5)?;
                Ok(body_bytes)
            }
        }
    }

    fn gen_h1(&mut self) -> HlsResult<&mut Buffer> {
        let param = self.req_param();
        param.header.write_to(param.addr.host(), param.body.len(), param.buffer)?;
        param.buffer.write_slice(b"\r\n");
        if let Some(context_type) = param.header.content_type() && let ContentType::File(md5) = context_type {
            param.body.write_to(param.buffer, md5);
        } else {
            param.body.write_to(param.buffer, "")
        }
        Ok(param.buffer)
    }

    fn gen_h2_header(&mut self) -> HlsResult<Vec<HeaderKey>> {
        let mut headers = self.header().as_h2c()?;
        headers.insert(1, HeaderKey::new(":authority".to_string(), HeaderValue::String(self.addr().to_string().replace(":80", "").replace(":443", ""))));
        headers.insert(2, HeaderKey::new(":scheme".to_string(), HeaderValue::String(self.scheme().to_string())));
        headers.insert(3, HeaderKey::new(":path".to_string(), HeaderValue::String(self.header().uri().to_string())));
        Ok(headers)
    }


    fn gen_h2_body(&mut self) -> HlsResult<Vec<u8>> {
        self.format_body("abcde12345abcdebbeeaaccafeacb454")
    }
}