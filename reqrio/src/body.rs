use crate::error::HlsResult;
use crate::form_data::{HttpFile, HttpFileBuffer};
use crate::packet::H2FrameWBufs;
use crate::reader::{ReadExt, Reader};
use reqtls::WriteExt;
use std::io::{Cursor, Read};

pub(crate) enum BodyType {
    Bytes(Cursor<Vec<u8>>),
    Files(HttpFile),
}

impl BodyType {
    pub fn new_byte(bytes: Vec<u8>) -> Self {
        BodyType::Bytes(Cursor::new(bytes))
    }

    pub fn len(&self) -> usize {
        match self {
            BodyType::Bytes(b) => b.get_ref().len(),
            BodyType::Files(f) => f.len()
        }
    }

    pub fn as_buffer(&mut self) -> BodyTypeBuffer<'_> {
        match self {
            BodyType::Bytes(bs) => BodyTypeBuffer::Bytes(bs),
            BodyType::Files(hfs) => BodyTypeBuffer::Files(hfs.as_buffer())
        }
    }
}


pub(crate) enum BodyTypeBuffer<'a> {
    Bytes(&'a mut Cursor<Vec<u8>>),
    Files(HttpFileBuffer<'a>),
}

impl<'a> BodyTypeBuffer<'a> {
    pub fn len(&self) -> usize {
        match self {
            BodyTypeBuffer::Bytes(bs) => bs.get_ref().len(),
            BodyTypeBuffer::Files(hfs) => hfs.len(),
        }
    }
}

impl<'a> ReadExt for BodyTypeBuffer<'a> {
    fn wrote(&self) -> bool {
        match self {
            BodyTypeBuffer::Bytes(bs) => bs.position() as usize == bs.get_ref().len(),
            BodyTypeBuffer::Files(fs) => fs.wrote(),
        }
    }
    fn read(&mut self, buf: &mut Reader) -> HlsResult<usize> {
        match self {
            BodyTypeBuffer::Bytes(bs) => {
                let len = bs.read(buf.unfilled())?;
                buf.add_len(len);
                Ok(len)
            }
            BodyTypeBuffer::Files(hfs) => hfs.read(buf),
        }
    }
}

pub(crate) enum BodyBuffer<'a> {
    HTTP1(BodyTypeBuffer<'a>),
    HTTP2(H2FrameWBufs<'a>),
}

impl<'a> ReadExt for BodyBuffer<'a> {
    fn wrote(&self) -> bool {
        match self {
            BodyBuffer::HTTP1(h1) => h1.wrote(),
            BodyBuffer::HTTP2(h2) => h2.wrote(),
        }
    }

    fn read(&mut self, buf: &mut Reader) -> HlsResult<usize> {
        match self {
            BodyBuffer::HTTP1(h1) => h1.read(buf),
            BodyBuffer::HTTP2(h2) => h2.read(buf)
        }
    }
}