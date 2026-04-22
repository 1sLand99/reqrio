use crate::body::{Body, H2FrameRBuf};
use crate::ext::{ReqParam, ReqPriExt};
use crate::hpack::HPackCoding;
use crate::packet::{FrameFlag, HeaderParam};
use crate::reader::{ReadExt, Reader};
use crate::request::RequestBuffer;
use crate::stream::{ConnParam, Stream};
use crate::*;
use json::JsonValue;
use std::convert::Infallible;
use std::path::{Path, PathBuf};

#[repr(C)]
pub struct ScReq {
    header: Header,
    stream: Stream,
    callback: Option<ReqCallback>,
    timeout: Timeout,
    stream_id: u32,
    proxy: Proxy,
    fingerprint: Fingerprint,
    verify: bool,
    auto_redirect: bool,
    buffer: Buffer,
    hpack_coder: HPackCoding,
    certs: Vec<Certificate>,
    key: RsaKey,
    ca_certs: Vec<Certificate>,
    alpn: ALPN,
    key_log: Option<PathBuf>,
    host: String,
}

impl Default for ScReq {
    fn default() -> Self {
        ScReq {
            header: Header::new_req_h1(),
            stream: Stream::NonConnection,
            callback: None,
            timeout: Timeout::default(),
            stream_id: 0,
            proxy: Proxy::Null,
            fingerprint: Fingerprint::default(),
            verify: true,
            auto_redirect: true,
            buffer: Buffer::with_capacity(32826),
            hpack_coder: HPackCoding::new(4096),
            certs: vec![],
            key: RsaKey::none(),
            ca_certs: vec![],
            alpn: ALPN::Http20,
            key_log: None,
            host: "".to_string(),
        }
    }
}

impl ScReq {
    pub fn new() -> ScReq {
        ScReq::default()
    }

    pub fn get<'a, E>(&mut self, url: impl TryInto<Url, Error=E>, body: impl Into<Body<'a>>) -> HlsResult<Response>
    where
        HlsError: From<E>,
    {
        self.header.set_method(Method::GET);
        self.stream_io(url, body.into())
    }

    pub fn post<'a, E>(&mut self, url: impl TryInto<Url, Error=E>, body: impl Into<Body<'a>>) -> HlsResult<Response>
    where
        HlsError: From<E>,
    {
        self.header.set_method(Method::POST);
        self.stream_io(url, body.into())
    }

    pub fn put<'a, E>(&mut self, url: impl TryInto<Url, Error=E>, body: impl Into<Body<'a>>) -> HlsResult<Response>
    where
        HlsError: From<E>,
    {
        self.header.set_method(Method::PUT);
        self.stream_io(url, body.into())
    }

    pub fn options<'a, E>(&mut self, url: impl TryInto<Url, Error=E>, body: impl Into<Body<'a>>) -> HlsResult<Response>
    where
        HlsError: From<E>,
    {
        self.header.set_method(Method::OPTIONS);
        self.stream_io(url, body.into())
    }

    pub fn delete<'a, E>(&mut self, url: impl TryInto<Url, Error=E>, body: impl Into<Body<'a>>) -> HlsResult<Response>
    where
        HlsError: From<E>,
    {
        self.header.set_method(Method::DELETE);
        self.stream_io(url, body.into())
    }

    pub fn head<'a, E>(&mut self, url: impl TryInto<Url, Error=E>, body: impl Into<Body<'a>>) -> HlsResult<Response>
    where
        HlsError: From<E>,
    {
        self.header.set_method(Method::HEAD);
        self.stream_io(url, body.into())
    }

    pub fn trace<'a, E>(&mut self, url: impl TryInto<Url, Error=E>, body: impl Into<Body<'a>>) -> HlsResult<Response>
    where
        HlsError: From<E>,
    {
        self.header.set_method(Method::TRACE);
        self.stream_io(url, body.into())
    }

    pub fn patch<'a, E>(&mut self, url: impl TryInto<Url, Error=E>, body: impl Into<Body<'a>>) -> HlsResult<Response>
    where
        HlsError: From<E>,
    {
        self.header.set_method(Method::PATCH);
        self.stream_io(url, body.into())
    }

    pub fn h1_io(&mut self) -> HlsResult<Response> {
        let mut response = Response::new();
        let mut read_len = 0;
        loop {
            self.stream.sync_read(&mut self.buffer)?;
            if self.handle_h1_res(&mut response, &mut read_len)? { break; }
        }
        Ok(response)
    }

    pub(crate) fn handle_io(&mut self, url: &Url, body: &Body) -> HlsResult<Response> {
        let mut request = RequestBuffer::new(&mut self.header, body, HeaderParam {
            url,
            stream_identifier: &self.stream_id,
            encoder: self.hpack_coder.encoder(),
            body_len: 0,
        })?;
        self.buffer.reset();
        loop {
            let mut render = Reader::new(self.buffer.unfilled_mut());
            let len = request.read(&mut render)?;
            if len == 0 { break; }
            self.stream.sync_write(render.filled())?;
        }
        let response = match self.header.alpn() {
            ALPN::Http20 => self.h2c_io(),
            _ => self.h1_io()
        }?;
        self.update_cookie(&response);
        self.callback = None;
        if let ALPN::Http20 = self.header.alpn() { self.stream_id += 2; }
        Ok(response)
    }

    pub fn stream_io<E>(&mut self, url: impl TryInto<Url, Error=E>, body: Body) -> HlsResult<Response>
    where
        HlsError: From<E>,
    {
        let mut url = url.try_into()?;
        self.set_url(&url)?;
        for i in 0..self.timeout.handle_times() {
            let res = self.handle_io(&url, &body);
            self.buffer.reset();
            match res {
                Ok(res) => {
                    let code = res.header().status().code();
                    return if self.auto_redirect && (300..400).contains(&code) {
                        let location = res.header().location().ok_or("missing location")?;
                        match location.starts_with("http") {
                            true => url = Url::try_from(location)?,
                            false => url.set_uri(location)?
                        };
                        self.header.set_method(Method::GET);
                        self.stream_io::<Infallible>(url, Body::none())
                    } else {
                        Ok(res)
                    };
                }
                Err(e) => if i < self.timeout.handle_times() - 1 {
                    if self.timeout.is_peer_closed(e.to_string()) {
                        self.re_conn(&url)?;
                    }
                    println!("[ScReq] write/recv error, error: {}, handle: {}/{}", e, i + 2, self.timeout.handle_times());
                    continue;
                } else { return Err(e) }
            }
        }
        Err("stream io error".into())
    }

    pub fn re_conn(&mut self, url: &Url) -> HlsResult<()> {
        self.buffer.reset();
        for i in 0..self.timeout.connect_times() {
            let param = ConnParam {
                url,
                proxy: &self.proxy,
                timeout: &self.timeout,
                fingerprint: &mut self.fingerprint,
                alpn: &self.alpn,
                verify: self.verify,
                cert: &mut self.certs,
                key: &self.key,
                ca_cert: &self.ca_certs,
                key_log: &self.key_log,
            };
            match self.stream.sync_conn(param) {
                Ok(alpn) => {
                    self.header.init_by_alpn(alpn);
                    if self.header.alpn() == &ALPN::Http20 { self.handle_h2_setting()?; }
                    self.host = url.sni().to_string();
                    return Ok(());
                }
                Err(e) => if i < self.timeout.connect_times() - 1 {
                    println!("[ScReq] continue with error-{}, handle: {}/{}", e, i + 2, self.timeout.handle_times());
                    continue;
                } else { return Err(e) }
            }
        }
        Err("[ScReq] connection error".into())
    }

    pub fn with_fingerprint(mut self, fingerprint: Fingerprint) -> Self {
        self.fingerprint = fingerprint;
        self
    }

    pub fn set_fingerprint(&mut self, fingerprint: Fingerprint) {
        self.fingerprint = fingerprint;
    }

    pub(crate) fn set_url(&mut self, url: &Url) -> HlsResult<()>
    {
        if self.host != url.sni() || self.stream.scheme() != Some(*url.scheme()) {
            self.re_conn(url)?;
        }
        Ok(())
    }

    pub fn send_check<'a, E>(&mut self, method: Method, url: impl TryInto<Url, Error=E>, body: impl Into<Body<'a>>) -> HlsResult<Response>
    where
        HlsError: From<E>,
    {
        self.header.set_method(method);
        let response = self.stream_io(url, body.into())?;
        self.check_status(&response)?;
        Ok(response)
    }

    pub fn send_check_json<'a, E>(
        &mut self,
        method: Method,
        url: impl TryInto<Url, Error=E>,
        body: impl Into<Body<'a>>,
        k: impl AsRef<str>,
        v: impl ToString,
        e: Vec<impl AsRef<str>>,
    ) -> HlsResult<JsonValue>
    where
        HlsError: From<E>,
    {
        let response = self.send_check(method, url, body.into())?;
        self.check_res(response, k, v, e)
    }
}

impl ScReq {
    pub fn handle_h2_setting(&mut self) -> HlsResult<()> {
        self.hpack_coder = HPackCoding::new(65536);
        self.stream_id = 0;
        self.buffer.write_slice(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")?;
        self.fingerprint.h2_setting().write_to(&mut self.buffer)?;
        self.fingerprint.h2_window_update().write_to(&mut self.buffer)?;
        // self.buffer.write_slice(self.fingerprint.h2_setting())?;
        // self.buffer.write_slice(self.fingerprint.h2_window_update())?;
        self.stream.sync_write(self.buffer.filled())?;
        self.buffer.reset();
        self.stream_id += 1;
        Ok(())
    }

    pub fn h2c_io(&mut self) -> HlsResult<Response> {
        let mut response = Response::new();
        loop {
            self.stream.sync_read(&mut self.buffer)?;
            while let Ok((frame_type, frame_flag, frame_len)) = H2FrameRBuf::buffer_enough(&self.buffer) {
                if frame_type == FrameType::Settings && frame_flag.end_stream() {
                    let mut end_frame = H2Frame::none_frame();
                    end_frame.set_frame_type(FrameType::Settings);
                    end_frame.set_flag(FrameFlag::EndStream);
                    self.stream.sync_write(end_frame.to_bytes().as_ref())?;
                    self.buffer.move_to(frame_len..self.buffer.len(), 0);
                    continue;
                }
                if self.handle_h2_res(frame_type, &mut response)? { return Ok(response); }
            }
        }
    }
}

impl ReqGenExt for ScReq {
    fn stream_mut(&mut self) -> &mut Stream {
        &mut self.stream
    }
}

impl ReqPriExt for ScReq {
    fn into_stream(self) -> Stream {
        self.stream
    }

    fn req_param(&mut self) -> ReqParam<'_> {
        ReqParam {
            header: &mut self.header,
            buffer: &mut self.buffer,
            hpack_coder: &mut self.hpack_coder,
            sid: &self.stream_id,
            callback: &mut self.callback,

        }
    }
}

impl ReqExt for ScReq {
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

    fn set_proxy(&mut self, proxy: Proxy) {
        self.proxy = proxy;
    }

    fn set_verify(&mut self, verify: bool) {
        self.verify = verify;
    }

    fn set_auto_redirect(&mut self, auto_redirect: bool) {
        self.auto_redirect = auto_redirect;
    }

    fn set_key_log(&mut self, path: impl AsRef<Path>) {
        self.key_log = Some(path.as_ref().to_owned());
    }

    fn set_alpn(&mut self, alpn: ALPN) {
        self.alpn = alpn;
    }

    fn set_mtls(&mut self, certs: Vec<Certificate>, key: RsaKey, ca: Option<Vec<Certificate>>) {
        self.certs = certs;
        self.ca_certs = ca.unwrap_or(vec![]);
        self.key = key;
    }

    fn set_callback(&mut self, callback: impl FnMut(&[u8]) -> HlsResult<()> + 'static) {
        self.callback = Some(Box::new(callback));
    }

    fn set_fingerprint(&mut self, fingerprint: Fingerprint) {
        self.fingerprint = fingerprint;
    }
}

#[cfg(feature = "export")]
unsafe impl Send for ScReq {}