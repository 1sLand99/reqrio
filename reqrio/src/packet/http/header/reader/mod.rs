mod h1;
mod h2;

use crate::error::HlsResult;
use crate::hpack::HPackEncode;
use crate::reader::{ReadExt, Writer};
pub(super) use h1::H1HeaderReader;
pub(super) use h2::H2HeaderReader;
use reqtls::Url;

pub struct HeaderParam<'a> {
    pub(crate) url: &'a Url,
    pub(crate) encoder: &'a mut HPackEncode,
    pub(crate) stream_identifier: &'a u32,
    pub(crate) body_len: usize,
    pub(crate) weight: &'a u8,
    pub(crate) priority: &'a bool,
}

pub enum HeaderReader<'a> {
    H1(H1HeaderReader<'a>),
    H2(H2HeaderReader<'a>),
}

impl<'a> ReadExt for HeaderReader<'a> {
    fn wrote(&self) -> bool {
        match self {
            HeaderReader::H1(h1) => h1.wrote(),
            HeaderReader::H2(h2) => h2.wrote(),
        }
    }

    fn len(&self) -> usize {
        match self {
            HeaderReader::H1(h1) => h1.len(),
            HeaderReader::H2(h2) => h2.len(),
        }
    }

    fn read(&mut self, buf: &mut Writer) -> HlsResult<usize> {
        match self {
            HeaderReader::H1(h1) => h1.read(buf),
            HeaderReader::H2(h2) => h2.read(buf),
        }
    }
}

