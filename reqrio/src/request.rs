use crate::body::{BodyType, BodyTypeBuffer};
use crate::error::HlsResult;
use crate::packet::HeaderBuffer;
use crate::reader::ReadExt;
use crate::{Buffer, ContentType, Header};
use reqtls::{Addr, Scheme, WriteExt};
use std::sync::Arc;

pub struct RequestBuffer<'a> {
    header: HeaderBuffer<'a>,
    header_wrote: bool,
    body: BodyTypeBuffer<'a>,
}

impl<'a> RequestBuffer<'a> {
    pub fn new(header: &'a mut Header, addr: &'a Addr, scheme: &'a Scheme, sid: &'a u32, body: &'a mut BodyType) -> RequestBuffer<'a> {
        let body_len = body.len();
        let body = if let Some(ct) = header.content_type() && let ContentType::File(md5) = ct {
            body.as_buffer(md5)
        } else { body.as_buffer(&Arc::new("".to_string())) };
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
    fn read(&mut self, buf: &mut Buffer) -> HlsResult<usize> {
        let start = buf.offset().end;
        if !self.header_wrote {
            self.header.read(buf)?;
            self.header_wrote = self.header.is_wrote();
        }
        self.body.read(buf)?;
        Ok(buf.offset().end - start)
    }
}