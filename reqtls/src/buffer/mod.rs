mod encode;
mod decode;
mod ext;
mod error;

use crate::ffi::CPointer;
pub use decode::RecordDecodeBuffer;
pub use encode::RecordEncodeBuffer;
pub use error::BufferError;
pub use ext::{ReadExt, WriteExt};
use std::fmt::{Debug, Formatter};
use std::ops::{Index, Range, RangeFrom};
use std::slice;

pub enum Buf<'a> {
    Ptr(BufPtr),
    Ref(&'a [u8]),
    Vec(Vec<u8>),
}

impl<'a> Buf<'a> {
    pub fn len(&self) -> usize {
        match self {
            Buf::Ptr(v) => v.len,
            Buf::Ref(v) => v.len(),
            Buf::Vec(v) => v.len()
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            Buf::Ptr(v) => v.as_slice().to_vec(),
            Buf::Ref(v) => v.to_vec(),
            Buf::Vec(v) => v.clone()
        }
    }
}

impl<'a> AsRef<[u8]> for Buf<'a> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Buf::Ptr(v) => v.as_slice(),
            Buf::Ref(v) => v,
            Buf::Vec(v) => v.as_slice(),
        }
    }
}

impl<'a> Debug for Buf<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Buf::Ptr(v) => write!(f, "{:?}", v),
            Buf::Ref(v) => write!(f, "{:?}", hex::encode(v)),
            Buf::Vec(v) => write!(f, "{:?}", hex::encode(v)),
        }
    }
}

pub struct BufPtr {
    ptr: CPointer<u8>,
    len: usize,
}

impl BufPtr {
    pub fn nullptr() -> Self {
        BufPtr {
            ptr: CPointer::nullptr(),
            len: 0,
        }
    }

    pub fn is_null(&self) -> bool { self.ptr.is_null() }

    pub fn ptr_mut(&mut self) -> &mut *mut u8 { self.ptr.as_mut() }

    pub fn len(&self) -> usize { self.len }

    pub fn check_ptr(&mut self, len: usize) -> Result<(), BufferError> {
        if self.is_null() || len == usize::MAX { return Err(BufferError::Nullptr); };
        self.len = len;
        Ok(())
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

impl Debug for BufPtr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.as_slice())
    }
}


pub struct WriteBuffer {
    buf: Vec<u8>,
    len: usize,
}

impl WriteBuffer {
    pub(crate) fn new(capacity: usize) -> WriteBuffer {
        WriteBuffer {
            buf: vec![0; capacity],
            len: 0,
        }
    }

    pub fn filled(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    pub fn reset(&mut self) { self.len = 0; }
}

impl WriteExt for WriteBuffer {
    fn as_ptr(&self) -> *const u8 {
        self.buf.as_ptr()
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.buf.as_mut_ptr()
    }

    fn add_len(&mut self, len: usize) {
        self.len += len;
    }

    fn offset(&self) -> Range<usize> {
        0..self.len
    }

    fn capacity(&self) -> usize {
        self.buf.capacity()
    }
}

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn from_slice(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn with_position(mut self, pos: usize) -> Self {
        self.pos = pos;
        self
    }
    pub fn unread_len(&self) -> usize {
        self.buf.len() - self.pos
    }
}

impl<'a> From<&'a [u8]> for Reader<'a> {
    fn from(buf: &'a [u8]) -> Self {
        Self::from_slice(buf)
    }
}

impl<'a> From<&'a Vec<u8>> for Reader<'a> {
    fn from(buf: &'a Vec<u8>) -> Self {
        Self::from_slice(buf.as_slice())
    }
}

impl<'a> ReadExt<'a> for Reader<'a> {
    fn position(&self) -> usize {
        self.pos
    }

    fn set_position(&mut self, pos: usize) {
        self.pos = pos;
    }

    fn as_slice(&self) -> &'a [u8] {
        self.buf
    }
}


impl<'a> Index<usize> for Reader<'a> {
    type Output = u8;
    fn index(&self, index: usize) -> &Self::Output {
        &self.buf[index]
    }
}

impl<'a> Index<Range<usize>> for Reader<'a> {
    type Output = [u8];
    fn index(&self, index: Range<usize>) -> &Self::Output {
        &self.buf[index]
    }
}

impl<'a> Index<RangeFrom<usize>> for Reader<'a> {
    type Output = [u8];
    fn index(&self, index: RangeFrom<usize>) -> &Self::Output {
        &self.buf[index]
    }
}
