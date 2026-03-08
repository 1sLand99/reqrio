use crate::body::BodyType;
use crate::error::HlsResult;
use crate::packet::HeaderBuffer;
use crate::reader::ReadExt;
use crate::Buffer;
use reqtls::WriteExt;

pub struct RequestBuffer<'a> {
    header: HeaderBuffer<'a>,
    header_wrote: bool,
    body: &'a mut BodyType,
}

impl<'a> RequestBuffer<'a> {
    pub fn new(mut hdr: HeaderBuffer<'a>, body: &'a mut BodyType) -> RequestBuffer<'a> {
        hdr.set_body_len(body.len());
        RequestBuffer {
            header: hdr,
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