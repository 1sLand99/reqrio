mod h1;
mod h2;

use reqtls::{Addr, Scheme};
use crate::error::HlsResult;
use crate::hpack::HPackEncode;
use crate::reader::{ReadExt, Reader};
pub(super) use h1::H1HeaderReader;
pub(super) use h2::H2HeaderReader;

pub struct HeaderParam<'a> {
    pub(crate) addr: &'a Addr,
    pub(crate) scheme: &'a Scheme,
    pub(crate) encoder: &'a mut HPackEncode,
    pub(crate) stream_identifier: &'a u32,
    pub(crate) body_len: usize,
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

    fn read(&mut self, buf: &mut Reader) -> HlsResult<usize> {
        match self {
            HeaderReader::H1(h1) => h1.read(buf),
            HeaderReader::H2(h2) => h2.read(buf),
        }
    }
}

