use std::path::Path;
use crate::body::H2FrameRBuf;
use crate::error::HlsResult;
use crate::hpack::HPackCoding;
use crate::packet::*;
use crate::reader::{ReadExt, Writer};
use crate::stream::Stream;
use crate::*;
use json::JsonValue;

pub(crate) struct ReqParam<'a> {
    pub(crate) header: &'a mut Header,
    pub(crate) buffer: &'a mut Buffer,
    pub(crate) hpack_coder: &'a mut HPackCoding,
    pub(crate) sid: &'a u32,
    pub(crate) callback: &'a mut Option<ReqCallback>,
}

#[allow(private_bounds)]
pub trait ReqExt: ReqPriExt + Sized {
    fn header_mut(&mut self) -> &mut Header;
    fn header(&self) -> &Header;
    fn with_timeout(mut self, timeout: Timeout) -> Self {
        self.set_timeout(timeout);
        self
    }
    fn set_timeout(&mut self, timeout: Timeout);
    fn timeout(&self) -> &Timeout;
    fn timeout_mut(&mut self) -> &mut Timeout;
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

    ///导出tls key log，不设置时读取SSLKEYLOGFILE环境变量，为保证通信安全，此功能仅Debug下起作用
    fn set_key_log(&mut self, path: impl AsRef<Path>);

    fn with_key_log(mut self, path: impl AsRef<Path>) -> Self {
        self.set_key_log(path);
        self
    }

    /// * 必须在建立tls连接（即：set_url/with_url）前设置, 否则需要调re_conn
    /// * 默认使用http2.0去连接，实际使用协议需要和服务器协商
    fn set_alpn(&mut self, alpn: ALPN);
    fn with_alpn(mut self, alpn: ALPN) -> Self {
        self.set_alpn(alpn);
        self
    }

    ///启用mtls，并传入客户端证书
    ///```no_run
    /// use reqrio::*;
    ///
    /// let mut req=ScReq::new();
    /// let certs=Certificate::from_pem_file("path/to/cert").unwrap();
    /// let key=RsaKey::from_pri_pem_file("path/to/cert/key").unwrap();
    /// req.set_mtls(certs,key,None);
    /// ```
    fn set_mtls(&mut self, certs: Vec<Certificate>, key: RsaKey, ca: Option<Vec<Certificate>>);
    fn with_mtls(mut self, certs: Vec<Certificate>, key: RsaKey, ca: Option<Vec<Certificate>>) -> Self {
        self.set_mtls(certs, key, ca);
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
}

pub(crate) trait ReqPriExt {
    fn into_stream(self) -> Stream;
    fn req_param(&mut self) -> ReqParam<'_>;

    fn read_to_vec<T: ReadExt>(mut reader: T) -> HlsResult<Vec<u8>> {
        let mut res = vec![0; 1024];
        let mut filled = 0;
        loop {
            let mut buf_reader = Writer::new(&mut res[filled..]);
            let len = reader.read(&mut buf_reader)?;
            filled += len;
            if reader.wrote() { break; }
            res.resize(res.capacity() + 1024, 0);
        }
        res.truncate(filled);
        Ok(res)
    }

    fn handle_h1_res(&mut self, response: &mut Response, rd: &mut usize) -> HlsResult<bool> {
        let param = self.req_param();
        match param.callback {
            None => response.extend_buffer(param.buffer),
            Some(callback) => {
                if response.header().is_empty() {
                    response.extend_buffer(param.buffer)?;
                    if !response.header().is_empty() {
                        callback(response.raw_body())?;
                        *rd += response.raw_body().len();
                        response.clear_raw();
                    }
                } else {
                    callback(param.buffer.filled())?;
                    *rd += param.buffer.filled().len();
                }
                if response.header().is_empty() { return Ok(false); }
                let finish = match response.header().content_length() {
                    None => param.buffer.filled().ends_with(&CHUNK_END),
                    Some(len) => *rd >= len
                };
                param.buffer.reset();
                Ok(finish)
            }
        }
    }

    fn handle_h2_res(&mut self, frame_type: FrameType, response: &mut Response) -> HlsResult<bool> {
        if frame_type == FrameType::Goaway { return Err(HlsError::PeerClosedConnection); }
        let param = self.req_param();
        let frame = H2FrameRBuf::from_bytes(param.buffer.filled(), frame_type)?;
        let res = match param.callback {
            None => response.extend_frame(&frame, param.hpack_coder.decoder()),
            Some(callback) => {
                match frame.frame_type() {
                    FrameType::Data => {
                        callback(frame.payload())?;
                        Ok(frame.is_end_frame())
                    }
                    FrameType::Headers => Ok(response.extend_frame(&frame, param.hpack_coder.decoder())?),
                    _ => Ok(false),
                }
            }
        };
        if let Some(max_size) = response.header().max_table_size() {
            param.hpack_coder.encoder().update_table_size(max_size);
        }
        param.buffer.move_to(frame.frame_len()..param.buffer.len(), 0);
        res
    }

    fn update_cookie(&mut self, response: &Response) {
        for cookie in response.header().cookies().unwrap_or(&vec![]) {
            if cookie.name() == "" && cookie.value() == "" { continue; }
            self.req_param().header.add_cookie(cookie.clone());
        }
    }

    fn check_status(&self,uri:&Url, response: &Response) -> HlsResult<()> {
        let status = response.header().status();
        match status.code() {
            400..600 => Err(format!("网络请求错误-{}({})", status,uri).into()),
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

pub trait ReqGenExt: ReqExt {
    fn stream_mut(&mut self) -> &mut Stream;

    /// * 最好在调试模式使用，生产模式使用时，一个请求将会产生两次reader，影响效率
    /// * H2严禁使用，否则影响hpack编码
    fn h1_raw_string(&mut self, url: &Url, body: &Body<'_>) -> HlsResult<String> {
        let body_raw = body.to_vec()?;
        let param = self.req_param();
        let header_reader = param.header.as_reader(HeaderParam {
            url,
            encoder: param.hpack_coder.encoder(),
            stream_identifier: param.sid,
            body_len: body_raw.len(),
            priority: &false,
            weight: &0,
        }, body.context_type());
        let mut header = Self::read_to_vec(header_reader)?;
        header.extend(body_raw);
        Ok(String::from_utf8_lossy(&header).to_string())
    }
}

pub trait UrlExt {
    fn params(&self, params: impl AsRef<JsonValue>) -> Result<Url, UrlError>;
    fn sni(&self, sni: impl Into<String>) -> Result<Url, UrlError>;
}

impl UrlExt for str {
    fn params(&self, params: impl AsRef<JsonValue>) -> Result<Url, UrlError> {
        let mut url = Url::try_from(self)?;
        for (key, value) in params.as_ref().entries() {
            match value {
                JsonValue::String(value) => url.uri_mut().insert_param(key, value),
                _ => url.uri_mut().insert_param(key, value.dump())
            }
        }
        Ok(url)
    }

    fn sni(&self, sni: impl Into<String>) -> Result<Url, UrlError> {
        Ok(Url::try_from(self)?.with_domain(sni))
    }
}

impl UrlExt for String {
    fn params(&self, params: impl AsRef<JsonValue>) -> Result<Url, UrlError> {
        self.as_str().params(params)
    }

    fn sni(&self, sni: impl Into<String>) -> Result<Url, UrlError> {
        Ok(Url::try_from(self)?.with_domain(sni))
    }
}