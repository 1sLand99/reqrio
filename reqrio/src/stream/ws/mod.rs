use crate::error::HlsResult;
use crate::stream::write::StreamShutdown;
use crate::stream::Stream;
use crate::*;

impl WebSocket {
    fn add_header(header: &mut Header) -> HlsResult<()> {
        if header.get_str("Sec-WebSocket-Key").unwrap_or("").is_empty() {
            header.insert("Sec-WebSocket-Key", "3eGwJ19k4qUKxRPJZUNYLw==")?
        }
        if header.get_str("Connection").unwrap_or("").is_empty() {
            header.set_connection("Upgrade")?;
        }
        if header.get_str("Sec-WebSocket-Version").unwrap_or("").is_empty() {
            header.insert("Sec-WebSocket-Version", "13")?
        }
        if header.get_str("Sec-WebSocket-Extensions").unwrap_or("").is_empty() {
            header.insert("Sec-WebSocket-Extensions", "permessage-deflate; client_max_window_bits")?
        }
        if header.get_str("Upgrade").unwrap_or("").is_empty() {
            header.insert("Upgrade", "websocket")?
        }
        Ok(())
    }

    pub fn open_sync(url: &str) -> HlsResult<WebSocket> {
        let mut header = Header::new_req_h1();
        WebSocket::add_header(&mut header)?;
        let mut req = ScReq::new().with_header(header);
        let resp = req.get(url, None)?;
        if resp.header().status() != HttpStatus::SwitchingProtocols {
            return Err("Connect Failed".into());
        }
        Ok(WebSocket::new(req.into_stream()?))
    }

    pub async fn open_async(url: &str) -> HlsResult<WebSocket> {
        let mut header = Header::new_req_h1();
        WebSocket::add_header(&mut header)?;
        let mut req = AcReq::new().with_header(header);
        let resp = req.get(url, None).await?;
        if resp.header().status() != HttpStatus::SwitchingProtocols {
            return Err("Connect Failed".into());
        }
        Ok(WebSocket::new(req.into_stream()?))
    }
}


#[cfg_attr(feature = "export", repr(C))]
pub struct WebSocket {
    stream: Stream,
    buffer: Buffer,
}

impl WebSocket {
    pub fn new_with_buffer(stream: Stream, buffer: Buffer) -> Self {
        Self { stream, buffer }
    }

    pub fn new(stream: Stream) -> Self {
        WebSocket::new_with_buffer(stream, Buffer::with_capacity(0xFFFF))
    }
}

impl WebSocket {
    pub fn write_frame(&mut self, frame: WsFrame) -> HlsResult<()> {
        self.stream.write(&frame.to_bytes()).wait()
    }

    pub fn read_frame(&mut self) -> HlsResult<WsFrame> {
        let frame = loop {
            if let Ok(frame) = WsFrame::from_buffer(&mut self.buffer) {
                break frame;
            }
            self.stream.read(&mut self.buffer).wait()?;
        };
        Ok(frame)
    }

    pub fn shutdown(&mut self) -> StreamShutdown<'_> {
        self.stream.shutdown()
    }
}

#[cfg(feature = "aync")]
impl WebSocket {
    pub async fn async_write_frame(&mut self, frame: WsFrame) -> HlsResult<()> {
        self.stream.write(&frame.to_bytes()).await
    }

    pub async fn async_read_frame(&mut self) -> HlsResult<WsFrame> {
        if let Ok(frame) = WsFrame::from_buffer(&mut self.buffer) {
            return Ok(frame);
        }
        loop {
            self.stream.read(&mut self.buffer).await?;
            if let Ok(frame) = WsFrame::from_buffer(&mut self.buffer) {
                return Ok(frame);
            }
        }
    }
}