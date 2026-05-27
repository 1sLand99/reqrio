use crate::body::{Body, H2FrameRBuf};
use crate::error::HlsResult;
use crate::ext::{ReqExt, ReqParam};
use crate::ext::{ReqGenExt, ReqPriExt};
use crate::hpack::HPackCoding;
use crate::json::JsonValue;
use crate::packet::{FrameFlag, FrameType, H2Frame, HeaderParam};
use crate::reader::{ReadExt, Writer};
use crate::request::RequestBuffer;
use crate::stream::{ConnParam, Proxy, Stream};
use crate::*;
use std::path::{Path, PathBuf};

pub struct AcReq {
    header: Header,
    stream: Stream,
    timeout: Timeout,
    callback: Option<ReqCallback>,
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
    url: Url,
}

impl Default for AcReq {
    fn default() -> Self {
        AcReq {
            header: Header::new_req_h1(),
            stream: Stream::NonConnection,
            timeout: Timeout::default(),
            callback: None,
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
            url: Default::default(),
        }
    }
}

impl AcReq {
    pub fn new() -> AcReq {
        AcReq::default()
    }

    pub async fn get<E>(&mut self, url: impl TryInto<Url, Error=E>, body: impl Into<Body<'_>>) -> HlsResult<Response>
    where
        HlsError: From<E>,
    {
        self.header.set_method(Method::GET);
        self.stream_io(&mut url.try_into()?, &body.into()).await
    }

    pub async fn post<E>(&mut self, url: impl TryInto<Url, Error=E>, body: impl Into<Body<'_>>) -> HlsResult<Response>
    where
        HlsError: From<E>,
    {
        self.header.set_method(Method::POST);
        self.stream_io(&mut url.try_into()?, &body.into()).await
    }

    pub async fn put<E>(&mut self, url: impl TryInto<Url, Error=E>, body: impl Into<Body<'_>>) -> HlsResult<Response>
    where
        HlsError: From<E>,
    {
        self.header.set_method(Method::PUT);
        self.stream_io(&mut url.try_into()?, &body.into()).await
    }

    pub async fn options<E>(&mut self, url: impl TryInto<Url, Error=E>, body: impl Into<Body<'_>>) -> HlsResult<Response>
    where
        HlsError: From<E>,
    {
        self.header.set_method(Method::OPTIONS);
        self.stream_io(&mut url.try_into()?, &body.into()).await
    }

    pub async fn delete<E>(&mut self, url: impl TryInto<Url, Error=E>, body: impl Into<Body<'_>>) -> HlsResult<Response>
    where
        HlsError: From<E>,
    {
        self.header.set_method(Method::DELETE);
        self.stream_io(&mut url.try_into()?, &body.into()).await
    }

    pub async fn head<E>(&mut self, url: impl TryInto<Url, Error=E>, body: impl Into<Body<'_>>) -> HlsResult<Response>
    where
        HlsError: From<E>,
    {
        self.header.set_method(Method::HEAD);
        self.stream_io(&mut url.try_into()?, &body.into()).await
    }

    pub async fn trace<E>(&mut self, url: impl TryInto<Url, Error=E>, body: impl Into<Body<'_>>) -> HlsResult<Response>
    where
        HlsError: From<E>,
    {
        self.header.set_method(Method::TRACE);
        self.stream_io(&mut url.try_into()?, &body.into()).await
    }

    pub async fn patch<E>(&mut self, url: impl TryInto<Url, Error=E>, body: impl Into<Body<'_>>) -> HlsResult<Response>
    where
        HlsError: From<E>,
    {
        self.header.set_method(Method::PATCH);
        self.stream_io(&mut url.try_into()?, &body.into()).await
    }

    pub async fn h1_io(&mut self) -> HlsResult<Response> {
        let mut response = Response::new();
        let mut read_len = 0;
        loop {
            self.stream.async_read(&mut self.buffer).await?;
            if self.handle_h1_res(&mut response, &mut read_len)? { break; }
        }
        Ok(response)
    }

    pub async fn send(&mut self, url: &Url, body: &Body<'_>) -> HlsResult<()> {
        let mut request = RequestBuffer::new(&mut self.header, body, HeaderParam {
            url,
            encoder: self.hpack_coder.encoder(),
            stream_identifier: &self.stream_id,
            body_len: 0,
            priority: &self.fingerprint.h2().priority,
            weight: &self.fingerprint.h2().weight,
        })?;
        self.buffer.reset();
        loop {
            let mut writer = Writer::new(self.buffer.unfilled_mut());
            let len = request.read(&mut writer)?;
            if len == 0 { break; }
            self.stream.async_write(writer.filled()).await?;
        }
        Ok(())
    }

    pub(crate) async fn handle_io(&mut self, url: &Url, body: &Body<'_>) -> HlsResult<Response> {
        self.send(url, body).await?;
        let response = match self.header.alpn() {
            ALPN::Http20 => self.h2c_io().await,
            _ => self.h1_io().await
        }?;
        self.update_cookie(&response);
        self.callback = None;
        if let ALPN::Http20 = self.header.alpn() { self.stream_id += 2; }
        Ok(response)
    }

    pub async fn stream_io(&mut self, url: &mut Url, body: &Body<'_>) -> HlsResult<Response> {
        self.set_url(url).await?;
        for i in 1..=self.timeout.handle_times() {
            let res = tokio::time::timeout(self.timeout.handle(), self.handle_io(url, &body)).await;
            self.buffer.reset();
            match res {
                Err(_) => if i >= self.timeout.handle_times() { return Err(HlsError::Time(TimeError::HandleTimeout)) }
                Ok(Err(e)) => if i >= self.timeout.handle_times() {
                    return Err(e)
                } else if self.timeout.is_peer_closed(e.to_string()) {
                    self.re_conn(None).await?;
                },
                Ok(Ok(resp)) => {
                    let code = resp.header().status().code();
                    return if self.auto_redirect && (300..400).contains(&code) {
                        let location = resp.header().location().ok_or("missing location")?;
                        match location.starts_with("http") {
                            true => *url = Url::try_from(location)?,
                            false => url.set_uri(location)?,
                        }
                        self.header.set_method(Method::GET);
                        Box::pin(self.stream_io(url, &Body::none())).await
                    } else {
                        Ok(resp)
                    };
                }
            }
        }
        Err("stream io error".into())
    }

    pub async fn connect<E>(mut self, url: impl TryInto<Url, Error=E>) -> HlsResult<AcReq>
    where
        HlsError: From<E>,
    {
        let url = url.try_into()?;
        self.re_conn(Some(&url)).await?;
        Ok(self)
    }

    pub async fn re_conn(&mut self, url: Option<&Url>) -> HlsResult<()> {
        self.buffer.reset();
        for i in 1..=self.timeout.connect_times() {
            let param = ConnParam {
                url: url.unwrap_or(&self.url),
                proxy: &self.proxy,
                timeout: &self.timeout,
                fingerprint: &mut self.fingerprint,
                alpn: &self.alpn,
                verify: self.verify,
                cert: &mut self.certs,
                key: &mut self.key,
                ca_cert: &self.ca_certs,
                key_log: &self.key_log,
                ech: false,
            };
            let res = tokio::time::timeout(self.timeout.connect(), self.stream.async_conn(param)).await;
            match res {
                Err(_) => if i >= self.timeout.handle_times() { return Err(HlsError::Time(TimeError::ConnectTimeout)) }
                Ok(Err(e)) => if i >= self.timeout.handle_times() { return Err(e) }
                Ok(Ok(alpn)) => {
                    #[cfg(feature = "log")]
                    debug!("[AcReq] Connected | ALPN: {} | RemoteAddr: {}", alpn, url.unwrap_or(&self.url).addr());
                    self.header.init_by_alpn(alpn);
                    if self.header.alpn() == &ALPN::Http20 { self.handle_h2_setting().await?; }
                    if let Some(url) = url {
                        self.url = url.clone();
                    }
                    return Ok(());
                }
            }
            continue;
        }
        Err("[AcReq] connection error".into())
    }

    pub(crate) async fn set_url(&mut self, url: &Url) -> HlsResult<()> {
        if self.url.addr().host() != url.addr().host() || self.stream.scheme() != Some(*url.scheme()) {
            self.re_conn(Some(url)).await?;
        }
        Ok(())
    }

    pub async fn send_check<E>(&mut self, method: Method, url: impl TryInto<Url, Error=E>, body: impl Into<Body<'_>>) -> HlsResult<Response>
    where
        HlsError: From<E>,
    {
        self.header.set_method(method);
        let mut url = url.try_into()?;
        let response = self.stream_io(&mut url, &body.into()).await?;
        self.check_status(&url, &response)?;
        Ok(response)
    }

    pub async fn send_check_json<E>(&mut self, method: Method, url: impl TryInto<Url, Error=E>, body: impl Into<Body<'_>>,
                                    k: impl AsRef<str>, v: impl ToString, e: Vec<impl AsRef<str>>) -> HlsResult<JsonValue>
    where
        HlsError: From<E>,
    {
        let response = self.send_check(method, url, body).await?;
        self.check_res(response, k, v, e)
    }
}

impl AcReq {
    pub async fn handle_h2_setting(&mut self) -> HlsResult<()> {
        self.stream_id = 0;
        self.buffer.write_slice(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")?;
        self.fingerprint.h2().build_setting().write_to(&mut self.buffer)?;
        self.hpack_coder = HPackCoding::new(65536);
        self.fingerprint.h2().build_window_update().write_to(&mut self.buffer)?;
        self.stream.async_write(self.buffer.filled()).await?;
        self.buffer.reset();
        self.stream_id += 1;
        Ok(())
    }

    pub async fn h2c_io(&mut self) -> HlsResult<Response> {
        let mut response = Response::new();
        loop {
            self.stream.async_read(&mut self.buffer).await?;
            while let Ok((frame_type, frame_flag, frame_len)) = H2FrameRBuf::buffer_enough(&self.buffer) {
                if frame_type == FrameType::Settings && frame_flag.end_stream() {
                    let mut end_frame = H2Frame::none_frame();
                    end_frame.set_frame_type(FrameType::Settings);
                    end_frame.set_flag(FrameFlag::EndStream);
                    self.stream.async_write(end_frame.to_bytes().as_ref()).await?;
                    self.buffer.move_to(frame_len..self.buffer.len(), 0);
                    continue;
                }
                if self.handle_h2_res(frame_type, &mut response)? { return Ok(response); }
            }
        }
    }
}

impl ReqGenExt for AcReq {
    fn stream_mut(&mut self) -> &mut Stream {
        &mut self.stream
    }
}

impl ReqPriExt for AcReq {
    fn into_stream(self) -> Stream {
        self.stream
    }

    fn req_param(&mut self) -> ReqParam<'_> {
        ReqParam {
            header: &mut self.header,
            buffer: &mut self.buffer,
            hpack_coder: &mut self.hpack_coder,
            callback: &mut self.callback,
            sid: &self.stream_id,
        }
    }
}

impl ReqExt for AcReq {
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
        self.key_log = Some(path.as_ref().to_path_buf());
    }

    fn set_alpn(&mut self, alpn: ALPN) {
        self.alpn = alpn;
    }

    fn set_mtls(&mut self, certs: Vec<Certificate>, key: RsaKey, ca: Option<Vec<Certificate>>) {
        self.certs = certs;
        self.key = key;
        self.ca_certs = ca.unwrap_or(vec![]);
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