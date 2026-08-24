use crate::body::Body;
use crate::error::HlsResult;
use crate::stream::Stream;
use crate::*;
use crate::ext::ReqPriExt;

pub struct WebSocketBuilder<S: ReqExt>(S);

impl<S: ReqExt> WebSocketBuilder<S> {
    pub fn with_proxy(mut self, proxy: Proxy) -> WebSocketBuilder<S> {
        self.0.set_proxy(proxy);
        self
    }

    pub fn set_proxy(&mut self, proxy: Proxy) {
        self.0.set_proxy(proxy);
    }

    pub fn with_origin(mut self, origin: impl ToString) -> HlsResult<WebSocketBuilder<S>> {
        ReqExt::header_mut(&mut self.0).set_origin(origin)?;
        Ok(self)
    }

    pub fn with_cookie(mut self, cookie: impl AsRef<str>) -> HlsResult<WebSocketBuilder<S>> {
        ReqExt::header_mut(&mut self.0).set_cookie(cookie)?;
        Ok(self)
    }

    pub fn with_user_agent(mut self, user_agent: impl ToString) -> HlsResult<WebSocketBuilder<S>> {
        ReqExt::header_mut(&mut self.0).set_user_agent(user_agent)?;
        Ok(self)
    }

    pub fn with_header(mut self, key: impl AsRef<str>, val: impl ToString) -> HlsResult<WebSocketBuilder<S>> {
        self.add_header(key, val)?;
        Ok(self)
    }

    pub fn add_header(&mut self, key: impl AsRef<str>, val: impl ToString) -> HlsResult<()> {
        ReqExt::header_mut(&mut self.0).insert(key, val)
    }

    pub fn set_uri(&mut self, uri: impl TryInto<Uri>) -> Result<(), RlsError> {
        ReqExt::header_mut(&mut self.0).set_uri(uri.try_into().map_err(|_| UrlError::ParseUriError)?);
        Ok(())
    }

    pub fn with_uri(mut self, uri: impl TryInto<Uri>) -> HlsResult<WebSocketBuilder<S>> {
        self.set_uri(uri)?;
        Ok(self)
    }
}

impl WebSocketBuilder<ScReq> {
    pub fn build(mut self, url: &Url) -> HlsResult<WebSocket> {
        WebSocket::add_header(ReqExt::header_mut(&mut self.0))?;
        Ok(WebSocket::new(WebSocket::connect_sync(self.0, url, None)?))
    }
}

#[cfg(feature = "aync")]
impl WebSocketBuilder<AcReq> {
    pub async fn build(mut self, url: &str) -> HlsResult<WebSocket> {
        WebSocket::add_header(ReqExt::header_mut(&mut self.0))?;
        Ok(WebSocket::new(WebSocket::connect_async(self.0, url, None).await?))
    }
}


#[cfg_attr(feature = "export", repr(C))]
pub struct WebSocket {
    stream: Stream,
    buffer: Buffer,
}

impl WebSocket {
    fn add_header(headers: &mut Header) -> HlsResult<()> {
        match headers.get_mut("Sec-WebSocket-Key") {
            None => headers.insert("Sec-WebSocket-Key", "3eGwJ19k4qUKxRPJZUNYLw==")?,
            Some(value) => if value.to_string() == "" { *value = HeaderValue::String("3eGwJ19k4qUKxRPJZUNYLw==".to_string()) }
        }
        match headers.get_mut("Connection") {
            None => headers.set_connection("Upgrade")?,
            Some(value) => if value.to_string() == "" { headers.set_connection("Upgrade")? }
        }
        match headers.get_mut("Sec-WebSocket-Version") {
            None => headers.insert("Sec-WebSocket-Version", "13")?,
            Some(value) => if value.to_string() == "" { *value = HeaderValue::String("13".to_string()) }
        }
        // match headers.get_mut("Sec-WebSocket-Extensions") {
        //     None => headers.insert("Sec-WebSocket-Extensions", "permessage-deflate; client_max_window_bits")?,
        //     Some(value) => if value.to_string() == "" { *value = HeaderValue::String("permessage-deflate; client_max_window_bits".to_string()) }
        // }
        match headers.get_mut("Upgrade") {
            None => headers.insert("Upgrade", "websocket")?,
            Some(value) => if value.to_string() == "" { *value = HeaderValue::String("websocket".to_string()) }
        }
        Ok(())
    }
}

impl WebSocket {
    fn new(stream: Stream) -> Self {
        WebSocket {
            stream,
            buffer: Buffer::with_capacity(0xFFFF),
        }
    }
}

impl WebSocket {
    pub fn sync_build() -> WebSocketBuilder<ScReq> {
        WebSocketBuilder(ScReq::new().with_timeout(Timeout::longer()))
    }


    fn connect_sync(mut req: ScReq, url: &Url, raw: Option<&[u8]>) -> HlsResult<Stream> {
        let resp = match raw {
            None => req.do_http(Method::GET, url.clone(), Body::none())?,
            Some(raw) => {
                req.set_url(url)?;
                req.http_stream_mut().stream_mut()?.sync_write(raw)?;
                req.responses().insert(0, Response::new());
                req.recv(0)?
            }
        };
        let status = resp.header().status();
        if status != &HttpStatus::SwitchingProtocols { return Err(format!("Connect fail with code-{}", status).into()); }
        req.into_stream()
    }

    pub fn open(url: impl AsRef<str>) -> HlsResult<WebSocket> {
        Self::sync_build().build(&Url::try_from(url.as_ref())?)
    }

    pub fn open_raw(url: impl AsRef<str>, context: impl AsRef<[u8]>) -> HlsResult<WebSocket> {
        let req = ScReq::new().with_timeout(Timeout::longer());
        Ok(WebSocket::new(Self::connect_sync(req, &Url::try_from(url.as_ref())?, Some(context.as_ref()))?))
    }


    pub fn write_frame(&mut self, frame: WsFrame) -> HlsResult<()> {
        self.stream.sync_write(&frame.to_bytes())
    }

    pub fn read_frame(&mut self) -> HlsResult<WsFrame> {
        if let Ok(frame) = WsFrame::from_buffer(&mut self.buffer) {
            return Ok(frame);
        }
        loop {
            self.stream.sync_read(&mut self.buffer)?;
            if let Ok(frame) = WsFrame::from_buffer(&mut self.buffer) {
                return Ok(frame);
            }
        }
    }

    pub fn shutdown(mut self) -> HlsResult<()> {
        self.stream.sync_shutdown()
    }
}

#[cfg(feature = "aync")]
impl WebSocket {
    pub fn async_build() -> WebSocketBuilder<AcReq> {
        WebSocketBuilder(AcReq::new().with_timeout(Timeout::longer()))
    }

    async fn connect_async(mut req: AcReq, url: &str, raw: Option<&[u8]>) -> HlsResult<Stream> {
        let resp = match raw {
            None => req.do_http(Method::GET, url, &Body::none()).await?,
            Some(raw) => {
                let url = Url::try_from(url)?;
                req.set_url(&url).await?;
                req.http_stream_mut().stream_mut()?.async_write(raw).await?;
                req.responses().insert(0, Response::new());
                req.recv(0).await?
            }
        };
        let status = resp.header().status();
        if status != &HttpStatus::SwitchingProtocols { return Err(format!("Connect fail with code-{}", status).into()); }
        req.into_stream()
    }

    pub async fn open_async(url: impl AsRef<str>) -> HlsResult<WebSocket> {
        Self::async_build().build(url.as_ref()).await
    }

    pub async fn open_async_raw(url: impl AsRef<str>, context: impl AsRef<[u8]>) -> HlsResult<WebSocket> {
        let req = AcReq::new().with_timeout(Timeout::longer());
        Ok(WebSocket::new(Self::connect_async(req, url.as_ref(), Some(context.as_ref())).await?))
    }


    pub async fn async_write_frame(&mut self, frame: WsFrame) -> HlsResult<()> {
        self.stream.async_write(&frame.to_bytes()).await
    }

    pub async fn async_read_frame(&mut self) -> HlsResult<WsFrame> {
        if let Ok(frame) = WsFrame::from_buffer(&mut self.buffer) {
            return Ok(frame);
        }
        loop {
            self.stream.async_read(&mut self.buffer).await?;
            if let Ok(frame) = WsFrame::from_buffer(&mut self.buffer) {
                return Ok(frame);
            }
        }
    }

    pub async fn async_shutdown(mut self) -> HlsResult<()> {
        self.stream.async_shutdown().await
    }
}