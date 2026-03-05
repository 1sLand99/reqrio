use std::mem;
use crate::ext::ReqPriExt;
use crate::hpack::{HPackCoding, HackDecode};
use crate::stream::{ConnParam, Stream};
use crate::*;
use json::JsonValue;
use crate::packet::FrameFlag;

#[repr(C)]
pub struct ScReq {
    header: Header,
    scheme: Scheme,
    addr: Addr,
    hack_coder: HPackCoding,
    stream: Stream,
    body: BodyType,
    callback: Option<ReqCallback>,
    timeout: Timeout,
    stream_id: u32,
    proxy: Proxy,
    fingerprint: Fingerprint,
    verify: bool,
    auto_redirect: bool,
    buffer: Buffer,
    certs: Vec<Certificate>,
    key: RsaKey,
}

impl Default for ScReq {
    fn default() -> Self {
        ScReq {
            header: Header::new_req_h1(),
            scheme: Scheme::Http,
            addr: Addr::default(),
            hack_coder: HPackCoding::new(),
            stream: Stream::NonConnection,
            body: BodyType::Text("".to_string()),
            callback: None,
            timeout: Timeout::new(),
            stream_id: 0,
            proxy: Proxy::Null,
            fingerprint: Fingerprint::default(),
            verify: true,
            auto_redirect: true,
            buffer: Buffer::with_capacity(32826),
            certs: vec![],
            key: RsaKey::none(),
        }
    }
}

impl ScReq {
    pub fn new() -> ScReq {
        ScReq::default()
    }

    pub fn get(&mut self) -> HlsResult<Response> {
        self.header.set_method(Method::GET);
        self.stream_io()
    }

    pub fn post(&mut self) -> HlsResult<Response> {
        self.header.set_method(Method::POST);
        self.stream_io()
    }

    pub fn put(&mut self) -> HlsResult<Response> {
        self.header.set_method(Method::PUT);
        self.stream_io()
    }

    pub fn options(&mut self) -> HlsResult<Response> {
        self.header.set_method(Method::OPTIONS);
        self.stream_io()
    }

    pub fn delete(&mut self) -> HlsResult<Response> {
        self.header.set_method(Method::DELETE);
        self.stream_io()
    }

    pub fn head(&mut self) -> HlsResult<Response> {
        self.header.set_method(Method::HEAD);
        self.stream_io()
    }

    pub fn trace(&mut self) -> HlsResult<Response> {
        self.header.set_method(Method::TRACE);
        self.stream_io()
    }

    pub fn patch(&mut self) -> HlsResult<Response> {
        self.header.set_method(Method::PATCH);
        self.stream_io()
    }

    pub fn h1_io(&mut self, context: impl AsRef<[u8]>) -> HlsResult<Response> {
        self.stream.sync_write(context.as_ref())?;
        let mut response = Response::new();
        let mut buffer = Buffer::with_capacity(16437);
        let mut read_len = 0;
        loop {
            self.stream.sync_read(&mut buffer)?;
            if self.handle_h1_res(&mut buffer, &mut response, &mut read_len)? { break; }
        }
        Ok(response)
    }

    fn handle_io(&mut self) -> HlsResult<Response> {
        let response = match self.header.alpn() {
            ALPN::Http20 => {
                let headers = self.gen_h2_header()?;
                let body = self.gen_h2_body()?;
                self.h2c_io(headers, body)
            }
            _ => {
                let context = self.gen_h1()?;
                self.h1_io(context)
            }
        }?;
        self.update_cookie(&response);
        self.callback = None;
        if let ALPN::Http20 = self.header.alpn() { self.stream_id += 2; }
        Ok(response)
    }

    pub fn stream_io(&mut self) -> HlsResult<Response> {
        for i in 0..self.timeout.handle_times() {
            let res = self.handle_io();
            self.buffer.reset();
            match res {
                Ok(res) => {
                    let code = res.header().status().code();
                    return if self.auto_redirect && (300..400).contains(&code) {
                        let location = res.header().location().ok_or("missing location")?;
                        if location.starts_with("http") {
                            self.set_url(location)?;
                        } else {
                            self.header.set_uri(Uri::try_from(location)?);
                        }
                        self.header.set_method(Method::GET);
                        self.stream_io()
                    } else {
                        Ok(res)
                    };
                }
                Err(e) => if i != self.timeout.handle_times() - 1 {
                    if self.timeout.is_peer_closed(e.to_string()) {
                        self.re_conn()?;
                    }
                    println!("[ScReq] write/recv error, error: {}, handle: {}/{}", e, i + 2, self.timeout.handle_times());
                    continue;
                }
            }
        }
        Err("stream io error".into())
    }

    pub fn re_conn(&mut self) -> HlsResult<()> {
        self.hack_coder = HPackCoding::new();
        self.stream_id = 0;
        for i in 0..self.timeout.connect_times() {
            let param = ConnParam {
                scheme: &self.scheme,
                addr: &self.addr,
                proxy: &self.proxy,
                timeout: &self.timeout,
                fingerprint: &mut self.fingerprint,
                alpn: self.header.alpn(),
                verify: self.verify,
                cert: &mut self.certs,
                key: &self.key,
            };
            match self.stream.sync_conn(param) {
                Ok(alpn) => {
                    self.header.init_by_alpn(alpn);
                    if self.header.alpn() == &ALPN::Http20 { self.handle_h2_setting()?; }
                    return Ok(());
                }
                Err(e) => if i != self.timeout.connect_times() - 1 {
                    println!("[ScReq] continue with error-{}, handle: {}/{}", e, i + 2, self.timeout.handle_times());
                    continue;
                }
            }
        }
        Err("[ScReq] connection error".into())
    }

    pub fn with_url(mut self, url: impl AsRef<str>) -> HlsResult<Self> {
        self.set_url(url)?;
        Ok(self)
    }

    pub fn with_fingerprint(mut self, fingerprint: Fingerprint) -> Self {
        self.fingerprint = fingerprint;
        self
    }

    pub fn set_fingerprint(&mut self, fingerprint: Fingerprint) {
        self.fingerprint = fingerprint;
    }

    pub fn new_with_url(url: impl AsRef<str>) -> HlsResult<ScReq> {
        let mut res = Self::new();
        res.set_url(url)?;
        Ok(res)
    }

    pub fn set_url(&mut self, url: impl AsRef<str>) -> HlsResult<()> {
        let (scheme, addr, uri) = Url::try_from(url.as_ref())?.into_inner();
        let old_addr = mem::replace(&mut self.addr, addr);
        let old_scheme = mem::replace(&mut self.scheme, scheme);
        self.header.set_uri(uri);
        if old_addr.host() != self.addr.host() || self.scheme != old_scheme {
            let host = self.addr.to_string().replace(":80", "").replace(":443", "");
            self.header.set_host(host)?;
            self.re_conn()?;
        }
        Ok(())
    }

    pub fn send_check(&mut self, method: Method) -> HlsResult<Response> {
        self.header.set_method(method);
        let response = self.stream_io()?;
        self.check_status(&response)?;
        Ok(response)
    }

    pub fn send_check_json(&mut self, method: Method, k: impl AsRef<str>, v: impl ToString, e: Vec<impl AsRef<str>>) -> HlsResult<JsonValue> {
        let response = self.send_check(method)?;
        self.check_res(response, k, v, e)
    }
}

impl ScReq {
    pub fn handle_h2_setting(&mut self) -> HlsResult<()> {
        self.buffer.write_slice(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        let setting_frame = self.fingerprint.h2_setting().clone();
        setting_frame.write_to(&mut self.buffer);
        let update_frame = self.fingerprint.h2_window_update().clone();
        update_frame.write_to(&mut self.buffer);
        self.stream.sync_write(self.buffer.filled())?;
        self.buffer.reset();
        self.stream_id += 1;
        Ok(())
    }

    pub fn h2c_io(&mut self, headers: Vec<HeaderKey>, body: Vec<u8>) -> HlsResult<Response> {
        let hdr_bs = self.hack_coder.encode(headers)?;
        let mut header_frame = H2Frame::new_header(hdr_bs, body.len(), self.stream_id);
        header_frame.set_weight(146);
        header_frame.add_flag(FrameFlag::Priority);
        header_frame.write_to(&mut self.buffer);
        for body_frame in H2Frame::new_body(body, self.stream_id) {
            if self.buffer.unfilled_mut().len() < body_frame.payload().len() + 9 {
                self.stream.sync_write(self.buffer.filled())?;
                self.buffer.reset();
            }
            body_frame.write_to(&mut self.buffer);
        }
        self.stream.sync_write(self.buffer.filled())?;
        self.buffer.reset();
        let mut response = Response::new();
        loop {
            self.stream.sync_read(&mut self.buffer)?;
            while let Ok(frame) = H2Frame::from_bytes(&mut self.buffer) {
                if frame.frame_type() == &FrameType::Settings && frame.flag().end_stream() {
                    let mut end_frame = H2Frame::none_frame();
                    end_frame.set_frame_type(FrameType::Settings);
                    end_frame.set_flag(FrameFlag::EndStream);
                    self.stream.sync_write(end_frame.to_bytes().as_ref())?;
                    continue;
                }
                if self.handle_h2_res(frame, &mut response)? { return Ok(response); };
            }
        }
    }
}

impl ReqGenExt for ScReq {}

impl ReqPriExt for ScReq {
    fn into_stream(self) -> Stream {
        self.stream
    }
    fn callback(&mut self) -> &mut Option<ReqCallback> {
        &mut self.callback
    }

    fn hack_decoder(&mut self) -> &mut HackDecode {
        self.hack_coder.decoder()
    }

    fn addr(&self) -> &Addr {
        &self.addr
    }

    fn scheme(&self) -> &Scheme {
        &self.scheme
    }
}

impl ReqExt for ScReq {
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

    fn timeout_mut(&mut self) -> &mut Timeout {
        &mut self.timeout
    }

    fn url(&self) -> String {
        format!("{}://{}{}", self.scheme, self.addr, self.header.uri()).replace(":80", "").replace(":443", "")
    }

    fn set_proxy(&mut self, proxy: Proxy) {
        self.proxy = proxy;
    }

    fn set_verify(&mut self, verify: bool) {
        self.verify = verify;
    }

    fn set_auto_redirect(&mut self, auto_redirect: bool) {
        self.auto_redirect = auto_redirect;
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

// impl Drop for ScReq {
//     fn drop(&mut self) {
//         let _ = self.stream.sync_shutdown();
//     }
// }

#[cfg(feature = "export")]
unsafe impl Send for ScReq {}