use std::borrow::Cow;
use crate::body::Body;
use crate::ext::{ReqParam, ReqPriExt};
use crate::stream::{ConnParam, HTTPStream, Stream};
use crate::*;
use json::JsonValue;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

pub struct ScReq {
    header: Header,
    stream: HTTPStream,
    callback: Option<ReqCallback>,
    timeout: Timeout,
    stream_id: u32,
    proxy: Proxy,
    fingerprint: Fingerprint,
    verify: bool,
    auto_redirect: bool,
    certs: Vec<Certificate>,
    key: RsaKey,
    ca_certs: Vec<Certificate>,
    alpn: ALPN,
    key_log: Option<PathBuf>,
    url: Url,
    tls_session: Option<TlsSession>,
    pub(crate) ignore_order: bool,
    responses: HashMap<u64, Response>,
    recv_ids: HashSet<u64>,
}

impl Default for ScReq {
    fn default() -> Self {
        ScReq {
            header: Header::default(),
            stream: HTTPStream::NonConnection,
            callback: None,
            timeout: Timeout::default(),
            stream_id: 0,
            proxy: Proxy::Null,
            fingerprint: Fingerprint::default(),
            verify: true,
            auto_redirect: true,
            certs: vec![],
            key: RsaKey::none(),
            ca_certs: vec![],
            alpn: ALPN::Http20,
            key_log: None,
            url: Url::default(),
            tls_session: None,
            ignore_order: false,
            responses: HashMap::with_capacity(100),
            recv_ids: HashSet::new(),
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
        self.stream_io(Method::GET, url, &body.into())
    }

    pub fn post<'a, E>(&mut self, url: impl TryInto<Url, Error=E>, body: impl Into<Body<'a>>) -> HlsResult<Response>
    where
        HlsError: From<E>,
    {
        self.stream_io(Method::POST, url, &body.into())
    }

    pub fn put<'a, E>(&mut self, url: impl TryInto<Url, Error=E>, body: impl Into<Body<'a>>) -> HlsResult<Response>
    where
        HlsError: From<E>,
    {
        self.stream_io(Method::PUT, url, &body.into())
    }

    pub fn options<'a, E>(&mut self, url: impl TryInto<Url, Error=E>, body: impl Into<Body<'a>>) -> HlsResult<Response>
    where
        HlsError: From<E>,
    {
        self.stream_io(Method::OPTIONS, url, &body.into())
    }

    pub fn delete<'a, E>(&mut self, url: impl TryInto<Url, Error=E>, body: impl Into<Body<'a>>) -> HlsResult<Response>
    where
        HlsError: From<E>,
    {
        self.stream_io(Method::DELETE, url, &body.into())
    }

    pub fn head<'a, E>(&mut self, url: impl TryInto<Url, Error=E>, body: impl Into<Body<'a>>) -> HlsResult<Response>
    where
        HlsError: From<E>,
    {
        self.stream_io(Method::HEAD, url, &body.into())
    }

    pub fn trace<'a, E>(&mut self, url: impl TryInto<Url, Error=E>, body: impl Into<Body<'a>>) -> HlsResult<Response>
    where
        HlsError: From<E>,
    {
        self.stream_io(Method::TRACE, url, &body.into())
    }

    pub fn patch<'a, E>(&mut self, url: impl TryInto<Url, Error=E>, body: impl Into<Body<'a>>) -> HlsResult<Response>
    where
        HlsError: From<E>,
    {
        self.stream_io(Method::PATCH, url, &body.into())
    }

    /// 发送一个请求，发送前务必确保链接已建立
    pub fn send<'a>(&mut self, method: Method, url: &Url, body: impl Into<&'a Body<'a>>) -> HlsResult<u64> {
        self.header.set_method(method);
        self.set_url(&url)?;
        let sid = self.stream.send(&url, &self.header, body.into(), &self.fingerprint)?;
        self.responses.insert(sid, Response::new());
        Ok(sid)
    }

    pub fn recv(&mut self, sid: u64) -> HlsResult<Response> {
        if self.recv_ids.remove(&sid) { return Ok(self.responses.remove(&sid).ok_or("missing response")?); }
        let msid = self.responses.keys().map(|x| x).min().unwrap_or(&sid);
        for _ in *msid..=sid {
            loop {
                let ids = self.stream.recv(&mut self.responses)?;
                let is_empty = ids.is_empty();
                ids.into_iter().for_each(|id| { self.recv_ids.insert(id); });
                if self.recv_ids.remove(&sid) { return Ok(self.responses.remove(&sid).ok_or("missing response")?); }
                if !is_empty { break; }
            }
        }
        Err("recv target sid failed".into())
    }


    fn handle_recv(&mut self, sid: u64) -> HlsResult<Response> {
        let resp = self.recv(sid)?;
        let code = resp.header().status().code();
        if self.auto_redirect && (300..400).contains(&code) {
            let location = resp.header().location().ok_or("missing location")?;
            let location = match location.starts_with("http") {
                true => Url::try_from(location)?,
                false => Url::try_from(format!("{}://{}{}", self.url.scheme(), self.url.addr(), location))?
            };
            let sid = self.send(Method::GET, &location, &Body::none())?;
            self.handle_recv(sid)?;
        }
        Ok(resp)
    }

    pub fn stream_io<'a, U>(&mut self, method: Method, url: U, body: impl Into<Body<'a>>) -> HlsResult<Response>
    where
        U: TryInto<Url>,
        HlsError: From<U::Error>,
    {
        let url = url.try_into()?;
        let body = body.into();
        for i in 1..=self.timeout.handle_times() {
            let sid = self.send(method, &url, &body)?;
            let res = self.handle_recv(sid);
            match res {
                Ok(res) => return Ok(res),
                Err(e) => if i >= self.timeout.handle_times() {
                    return Err(e);
                } else if self.timeout.is_peer_closed(e.to_string()) {
                    self.re_conn(None)?;
                }
            }
        }
        Err("stream io error".into())
    }

    pub fn connect<E>(mut self, url: impl TryInto<Url, Error=E>) -> HlsResult<ScReq>
    where
        HlsError: From<E>,
    {
        let url = url.try_into()?;
        self.re_conn(Some(&url))?;
        Ok(self)
    }

    pub fn re_conn(&mut self, url: Option<&Url>) -> HlsResult<()> {
        for i in 1..=self.timeout.connect_times() {
            let param = ConnParam {
                url: url.unwrap_or(&self.url),
                proxy: &self.proxy,
                timeout: &self.timeout,
                fingerprint: &mut self.fingerprint,
                alpn: &self.alpn,
                verify: self.verify,
                cert: &mut self.certs,
                key: &self.key,
                ca_cert: &self.ca_certs,
                key_log: &self.key_log,
                ech: false,
                session: &self.tls_session,
            };
            match self.stream.sync_conn(param) {
                Ok(alpn) => {
                    #[cfg(feature = "log")]
                    debug!("[AcReq] Connected | ALPN: {} | RemoteAddr: {}", alpn, url.unwrap_or(&self.url).addr());
                    self.tls_session = None;
                    if !self.ignore_order { self.header.init_by_alpn(alpn); }
                    if let Some(url) = url { self.url = url.clone(); }
                    return Ok(());
                }
                Err(e) => if i >= self.timeout.connect_times() {
                    return Err(e);
                }
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

    pub(crate) fn set_url(&mut self, url: &Url) -> HlsResult<()> {
        if self.url.addr().host() != url.addr().host() || url.scheme() != self.stream.scheme() {
            self.re_conn(Some(url))?;
        }
        Ok(())
    }

    pub fn send_check<'a, U>(&mut self, method: Method, url: U, body: impl Into<Body<'a>>) -> HlsResult<Response>
    where
        U: TryInto<Url> + Clone,
        HlsError: From<U::Error>,
    {
        let response = self.stream_io(method, url.clone(), &body.into())?;
        self.check_status(&url.try_into()?, &response)?;
        Ok(response)
    }

    pub fn send_check_json<'a, U>(
        &mut self,
        method: Method,
        url: U,
        body: impl Into<Body<'a>>,
        k: impl AsRef<str>,
        v: impl ToString,
        e: Vec<impl AsRef<str>>,
    ) -> HlsResult<JsonValue>
    where
        U: TryInto<Url> + Clone,
        HlsError: From<U::Error>,
    {
        let response = self.send_check(method, url, body.into())?;
        self.check_res(response, k, v, e)
    }
}

// impl ReqGenExt for ScReq {
//     fn stream_mut(&mut self) -> &mut Stream {
//         &mut self.stream
//     }
// }

impl ReqPriExt for ScReq {
    fn into_stream(self) -> Stream {
        // self.stream
        todo!()
    }

    fn req_param(&mut self) -> ReqParam<'_> {
        // ReqParam {
        //     header: &mut self.header,
        //     buffer: &mut self.buffer,
        //     hpack_coder: &mut self.hpack_coder,
        //     sid: &self.stream_id,
        //     callback: &mut self.callback,
        //
        // }
        todo!()
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

    fn proxy(&self) -> &Proxy { &self.proxy }

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

    fn set_tls_session(&mut self, tls_session: Option<TlsSession>) {
        self.tls_session = tls_session;
    }

    fn tls_session(&self) -> &Option<TlsSession> {
        &self.tls_session
    }
    fn set_header_keys(&mut self, headers: Vec<HeaderKey>, keep_sort: bool) -> HlsResult<()> {
        self.ignore_order = keep_sort;
        self.header.set_by_keys(headers, keep_sort)?;
        Ok(())
    }
}

#[cfg(feature = "export")]
unsafe impl Send for ScReq {}