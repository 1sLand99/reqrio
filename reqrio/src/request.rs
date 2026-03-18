use crate::body::{BodyReader, BodyType};
use crate::error::HlsResult;
use crate::hpack::HPackEncode;
use crate::packet::{H2BodyReader, HeaderReader};
use crate::reader::{ReadExt, Reader};
use crate::Header;
use reqtls::{Addr, Scheme, WriteExt, ALPN};

pub struct RequestBuffer<'a> {
    header: HeaderReader<'a>,
    header_wrote: bool,
    body: BodyReader<'a>,
}

impl<'a> RequestBuffer<'a> {
    pub fn new(header: &'a mut Header, addr: &'a Addr, scheme: &'a Scheme, hapck_encoder: &'a mut HPackEncode, sid: &'a u32, body: &'a mut BodyType) -> HlsResult<RequestBuffer<'a>> {
        let body_len = body.len();
        let body = match header.alpn() {
            ALPN::Http20 => BodyReader::HTTP2(H2BodyReader::new_size(8192, body.as_reader()?, sid)),
            _ => BodyReader::HTTP1(body.as_reader()?)
        };
        let mut header = header.as_reader(addr, scheme, hapck_encoder, sid);
        header.set_body_len(body_len);
        Ok(RequestBuffer {
            header,
            header_wrote: false,
            body,
        })
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