use crate::error::HlsResult;
use crate::form_data::{HttpFile, HttpFileReader};
use crate::packet::H2BodyReader;
use crate::reader::{ReadExt, Reader};
use reqtls::WriteExt;
use std::io::{Cursor, Read};

pub(crate) enum BodyType {
    Bytes(Vec<u8>),
    Files(HttpFile),
}

impl BodyType {
    pub fn new_byte(bytes: Vec<u8>) -> Self {
        BodyType::Bytes(bytes)
    }

    pub fn len(&self) -> usize {
        match self {
            BodyType::Bytes(b) => b.len(),
            BodyType::Files(f) => f.len()
        }
    }

    pub fn as_reader(&self) -> HlsResult<H1BodyReader<'_>> {
        match self {
            BodyType::Bytes(bs) => Ok(H1BodyReader::Bytes(Cursor::new(bs))),
            BodyType::Files(hfs) => Ok(H1BodyReader::Files(hfs.as_reader()?))
        }
    }
}


pub(crate) enum H1BodyReader<'a> {
    Bytes(Cursor<&'a [u8]>),
    Files(HttpFileReader<'a>),
}

impl<'a> H1BodyReader<'a> {
    pub fn len(&self) -> usize {
        match self {
            H1BodyReader::Bytes(bs) => bs.get_ref().len(),
            H1BodyReader::Files(hfs) => hfs.len(),
        }
    }
}

impl<'a> ReadExt for H1BodyReader<'a> {
    fn wrote(&self) -> bool {
        match self {
            H1BodyReader::Bytes(bs) => bs.position() as usize == bs.get_ref().len(),
            H1BodyReader::Files(fs) => fs.wrote(),
        }
    }
    fn read(&mut self, buf: &mut Reader) -> HlsResult<usize> {
        match self {
            H1BodyReader::Bytes(bs) => {
                let len = bs.read(buf.unfilled())?;
                buf.add_len(len);
                Ok(len)
            }
            H1BodyReader::Files(hfs) => hfs.read(buf),
        }
    }
}

pub(crate) enum BodyReader<'a> {
    HTTP1(H1BodyReader<'a>),
    HTTP2(H2BodyReader<'a>),
}

impl<'a> ReadExt for BodyReader<'a> {
    fn wrote(&self) -> bool {
        match self {
            BodyReader::HTTP1(h1) => h1.wrote(),
            BodyReader::HTTP2(h2) => h2.wrote(),
        }
    }

    fn read(&mut self, buf: &mut Reader) -> HlsResult<usize> {
        match self {
            BodyReader::HTTP1(h1) => h1.read(buf),
            BodyReader::HTTP2(h2) => h2.read(buf)
        }
    }
}