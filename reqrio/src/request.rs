use crate::body::{BodyReader, BodyType};
use crate::error::HlsResult;
use crate::packet::{H2BodyReader, HeaderParam, HeaderReader2};
use crate::reader::{ReadExt, Reader};
use crate::Header;
use reqtls::{WriteExt, ALPN};

pub struct RequestBuffer<'a> {
    header: HeaderReader2<'a>,
    header_wrote: bool,
    body: BodyReader<'a>,
}

impl<'a> RequestBuffer<'a> {
    pub fn new(header: &'a mut Header, body: &'a mut BodyType, mut param: HeaderParam<'a>) -> HlsResult<RequestBuffer<'a>> {
        let body = match header.alpn() {
            ALPN::Http20 => BodyReader::HTTP2(H2BodyReader::new_size(8192, body.as_reader()?, param.stream_identifier)),
            _ => BodyReader::HTTP1(body.as_reader()?)
        };
        param.body_len = body.len();
        let header = header.as_reader(param);
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

    fn len(&self) -> usize {
        self.header.len() + self.body.len()
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