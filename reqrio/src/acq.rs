use crate::body::BodyType;
use crate::error::HlsResult;
use crate::ext::ReqExt;
use crate::ext::{ReqGenExt, ReqPriExt};
use crate::hpack::{HPackCoding, HackDecode};
use crate::json::JsonValue;
use crate::packet::{FrameFlag, FrameType, H2Frame, HeaderKey};
use crate::stream::{ConnParam, Proxy, Stream};
use crate::*;

pub struct AcReq {
    header: Header,
    url: Url,
    hack_coder: HPackCoding,
    stream: Stream,
    timeout: Timeout,
    callback: Option<ReqCallback>,
    stream_id: u32,
    body: BodyType,
    alpn: ALPN,
    proxy: Proxy,
    fingerprint: Fingerprint,
    verify: bool,
    buffer: Buffer,
    certs: Vec<Certificate>,
    key: RsaKey,
}

impl Default for AcReq {
    fn default() -> Self {
        AcReq {
            header: Header::new_req_h1(),
            url: Url::new(),
            hack_coder: HPackCoding::new(),
            stream: Stream::unconnection(),
            timeout: Timeout::new(),
            callback: None,
            stream_id: 0,
            alpn: ALPN::Http11,
            proxy: Proxy::Null,
            fingerprint: Fingerprint::default(),
            body: BodyType::Text("".to_string()),
            verify: true,
            buffer: Buffer::with_capacity(32826),
            certs: vec![],
            key: RsaKey::none(),
        }
    }
}

impl AcReq {
    pub fn new() -> AcReq {
        AcReq::default()
    }

    pub async fn get(&mut self) -> HlsResult<Response> {
        self.header.set_method(Method::GET);
        self.stream_io().await
    }

    pub async fn post(&mut self) -> HlsResult<Response> {
        self.header.set_method(Method::POST);
        self.stream_io().await
    }

    pub async fn put(&mut self) -> HlsResult<Response> {
        self.header.set_method(Method::PUT);
        self.stream_io().await
    }

    pub async fn options(&mut self) -> HlsResult<Response> {
        self.header.set_method(Method::OPTIONS);
        self.stream_io().await
    }

    pub async fn delete(&mut self) -> HlsResult<Response> {
        self.header.set_method(Method::DELETE);
        self.stream_io().await
    }

    pub async fn head(&mut self) -> HlsResult<Response> {
        self.header.set_method(Method::HEAD);
        self.stream_io().await
    }

    pub async fn trace(&mut self) -> HlsResult<Response> {
        self.header.set_method(Method::TRACE);
        self.stream_io().await
    }

    pub async fn patch(&mut self) -> HlsResult<Response> {
        self.header.set_method(Method::PATCH);
        self.stream_io().await
    }

    pub async fn h1_io(&mut self, context: impl AsRef<[u8]>) -> HlsResult<Response> {
        self.stream.async_write(context.as_ref()).await?;
        let mut response = Response::new();
        let mut buffer = Buffer::with_capacity(16413);
        let mut read_len = 0;
        loop {
            self.stream.async_read(&mut buffer).await?;
            if self.handle_h1_res(&mut buffer, &mut response, &mut read_len)? { break; }
        }
        Ok(response)
    }

    async fn handle_io(&mut self) -> HlsResult<Response> {
        let response = match self.stream.alpn() {
            ALPN::Http20 => {
                let headers = self.gen_h2_header()?;
                let body = self.gen_h2_body()?;
                self.h2c_io(headers, body).await
            }
            _ => {
                let context = self.gen_h1()?;
                self.h1_io(context).await
            }
        }?;
        self.update_cookie(&response);
        self.callback = None;
        if let ALPN::Http20 = self.stream.alpn() { self.stream_id += 2; }
        Ok(response)
    }

    pub async fn stream_io(&mut self) -> HlsResult<Response> {
        for i in 0..self.timeout.handle_times() {
            let res = tokio::time::timeout(self.timeout.handle(), self.handle_io()).await;
            self.buffer.reset();
            match &res {
                Ok(res) => if let Err(e) = res && i != self.timeout.handle_times() - 1 {
                    if e.to_string().to_lowercase().contains("close") || e.to_string().contains("中止了") || e.to_string().contains("关闭") {
                        self.re_conn().await?;
                    }
                    println!("[AcReq] write/recv with error-{}, handle: {}/{}", e, i + 2, self.timeout.handle_times());
                    continue;
                }
                Err(_) => if i != self.timeout.handle_times() - 1 {
                    println!("[AcReq] write/recv timeout, timeout: {:?}, handle: {}/{}", self.timeout.handle(), i + 2, self.timeout.handle_times());
                    continue;
                }
            }
            return match res {
                Ok(res) => res,
                Err(_) => Err(format!("handle timeout, handle:{}; timeout: {:?}", self.timeout.handle_times(), self.timeout.handle()).into())
            };
        }
        Err("stream io error".into())
    }

    pub async fn re_conn(&mut self) -> HlsResult<()> {
        self.hack_coder = HPackCoding::new();
        self.stream_id = 0;
        for i in 0..self.timeout.connect_times() {
            let param = ConnParam {
                url: &self.url,
                proxy: &self.proxy,
                timeout: &self.timeout,
                fingerprint: &mut self.fingerprint,
                alpn: &self.alpn,
                verify: self.verify,
                cert: &mut self.certs,
                key: &mut self.key,
            };
            let res = tokio::time::timeout(self.timeout.connect(), self.stream.async_connect(param)).await;
            match &res {
                Ok(res) => if let Err(e) = res && i != self.timeout.handle_times() - 1 {
                    println!("[AcReq] connect with error-{}, handle: {}/{}", e, i + 2, self.timeout.handle_times());
                    continue;
                }
                Err(e) => if i != self.timeout.handle_times() - 1 {
                    println!("[AcReq] connect error, error: {:?}, handle: {}/{}", e.to_string(), i + 2, self.timeout.handle_times());
                    continue;
                }
            }
            return match res {
                Ok(res) => match res {
                    Ok(_) => {
                        self.header.init_by_alpn(self.stream.alpn());
                        if self.stream.alpn() == &ALPN::Http20 { self.handle_h2_setting().await?; }
                        Ok(())
                    }
                    Err(e) => Err(e),
                },
                Err(_) => Err(format!("connect timeout, handle:{}; timeout: {:?}", self.timeout.handle_times(), self.timeout.connect()).into())
            };
        }
        Err("[AcReq] connection error".into())
    }

    pub async fn with_url(mut self, url: impl AsRef<str>) -> HlsResult<Self> {
        self.set_url(url).await?;
        Ok(self)
    }

    pub async fn new_with_url(url: impl AsRef<str>) -> HlsResult<AcReq> {
        let mut res = Self::new();
        res.set_url(url).await?;
        Ok(res)
    }

    pub async fn set_url(&mut self, url: impl AsRef<str>) -> HlsResult<()> {
        let old_host = self.url.addr().host().to_string();
        self.url = Url::try_from(url.as_ref())?;
        if self.url.addr().host() != old_host {
            let host = self.url.addr().to_string().replace(":80", "").replace(":443", "");
            self.header.set_host(host)?;
            self.re_conn().await?;
        }
        Ok(())
    }

    pub async fn send_check(&mut self, method: Method) -> HlsResult<Response> {
        self.header.set_method(method);
        let response = self.stream_io().await?;
        self.check_status(&response)?;
        Ok(response)
    }

    pub async fn send_check_json(&mut self, method: Method, k: impl AsRef<str>, v: impl ToString, e: Vec<impl AsRef<str>>) -> HlsResult<JsonValue> {
        let response = self.send_check(method).await?;
        self.check_res(response, k, v, e)
    }
}

impl AcReq {
    pub async fn handle_h2_setting(&mut self) -> HlsResult<()> {
        self.buffer.write_slice(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        let setting_frame = self.fingerprint.h2_setting().clone();
        setting_frame.write_to(&mut self.buffer);
        let update_frame = self.fingerprint.h2_window_update().clone();
        update_frame.write_to(&mut self.buffer);
        self.stream.async_write(self.buffer.filled()).await?;
        self.buffer.reset();
        self.stream_id += 1;
        Ok(())
    }

    pub async fn h2c_io(&mut self, headers: Vec<HeaderKey>, body: Vec<u8>) -> HlsResult<Response> {
        let hdr_bs = self.hack_coder.encode(headers)?;
        let mut header_frame = H2Frame::new_header(hdr_bs, body.len(), self.stream_id);
        header_frame.set_weight(146);
        header_frame.add_flag(FrameFlag::Priority);
        header_frame.write_to(&mut self.buffer);
        for body_frame in H2Frame::new_body(body, self.stream_id) {
            if self.buffer.unfilled_mut().len() < body_frame.payload().len() + 9 {
                self.stream.async_write(self.buffer.filled()).await?;
                self.buffer.reset();
            }
            body_frame.write_to(&mut self.buffer);
        }
        self.stream.async_write(self.buffer.filled()).await?;
        self.buffer.reset();
        let mut response = Response::new();
        // let mut buffer = Buffer::with_capacity(0xFFFF);
        loop {
            self.stream.async_read(&mut self.buffer).await?;
            while let Ok(frame) = H2Frame::from_bytes(&mut self.buffer) {
                if frame.frame_type() == &FrameType::Settings && frame.flag().end_stream() {
                    let mut end_frame = H2Frame::none_frame();
                    end_frame.set_frame_type(FrameType::Settings);
                    end_frame.set_flag(FrameFlag::EndStream);
                    self.stream.async_write(end_frame.to_bytes().as_ref()).await?;
                    continue;
                }
                if self.handle_h2_res(frame, &mut response)? { return Ok(response); };
            }
        }
    }
}

impl ReqGenExt for AcReq {}

impl ReqPriExt for AcReq {
    fn into_stream(self) -> Stream {
        self.stream
    }
    fn callback(&mut self) -> &mut Option<ReqCallback> {
        &mut self.callback
    }

    fn hack_decoder(&mut self) -> &mut HackDecode {
        self.hack_coder.decoder()
    }
}

impl ReqExt for AcReq {
    fn body_type(&self) -> &BodyType {
        &self.body
    }

    fn body_type_mut(&mut self) -> &mut BodyType {
        &mut self.body
    }

    fn header_mut(&mut self) -> &mut Header {
        &mut self.header
    }

    fn header(&self) -> &Header {
        &self.header
    }

    fn set_timeout(&mut self, timeout: Timeout) {
        self.timeout = timeout;
    }

    fn timeout(&self) -> &Timeout {
        &self.timeout
    }

    fn url(&self) -> &Url {
        &self.url
    }

    fn url_mut(&mut self) -> &mut Url {
        &mut self.url
    }

    fn set_proxy(&mut self, proxy: Proxy) {
        self.proxy = proxy;
    }

    fn set_verify(&mut self, verify: bool) {
        self.verify = verify;
    }

    fn set_alpn(&mut self, alpn: ALPN) {
        self.alpn = alpn;
    }

    fn set_mtls(&mut self, certs: Vec<Certificate>, key: RsaKey) {
        self.certs = certs;
        self.key = key;
    }

    fn set_callback(&mut self, callback: impl FnMut(&[u8]) -> HlsResult<()> + 'static) {
        self.callback = Some(Box::new(callback));
    }

    fn set_fingerprint(&mut self, fingerprint: Fingerprint) {
        self.fingerprint = fingerprint;
    }
}

unsafe impl Send for AcReq {}

unsafe impl Sync for AcReq {}