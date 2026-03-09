use crate::body::{BodyBuffer, BodyType};
use crate::error::HlsResult;
use crate::packet::{H2FrameWBufs, HeaderBuffer};
use crate::reader::{ReadExt, Reader};
use crate::{ContentType, Header};
use reqtls::{Addr, Scheme, WriteExt, ALPN};
use std::sync::Arc;

pub struct RequestBuffer<'a> {
    header: HeaderBuffer<'a>,
    header_wrote: bool,
    body: BodyBuffer<'a>,
}

impl<'a> RequestBuffer<'a> {
    pub fn new(header: &'a mut Header, addr: &'a Addr, scheme: &'a Scheme, sid: &'a u32, body: &'a mut BodyType) -> RequestBuffer<'a> {
        let body_len = body.len();
        let body = if let Some(ct) = header.content_type() && let ContentType::File(md5) = ct {
            body.as_buffer(md5)
        } else { body.as_buffer(&Arc::new("".to_string())) };
        let body = match header.alpn() {
            ALPN::Http20 => BodyBuffer::HTTP2(H2FrameWBufs::new_size(8192, body, sid)),
            _ => BodyBuffer::HTTP1(body)
        };
        let mut header = HeaderBuffer::new(header, addr, scheme, sid);
        header.set_body_len(body_len);
        RequestBuffer {
            header,
            header_wrote: false,
            body,
        }
    }
}

impl<'a> ReadExt for RequestBuffer<'a> {
    fn wrote(&self) -> bool {
        self.body.wrote()
    }

    fn read(&mut self, buf: &mut Reader) -> HlsResult<usize> {
        let start = buf.offset().end;
        if !self.header_wrote {
            self.header.read(buf)?;
            self.header_wrote = self.header.wrote();
        }
        self.body.read(buf)?;
        Ok(buf.offset().end - start)
    }

}