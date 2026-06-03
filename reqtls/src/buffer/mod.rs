mod encode;
mod decode;
mod ext;
mod error;

use crate::ffi::CPointer;
pub use decode::RecordDecodeBuffer;
pub use encode::RecordEncodeBuffer;
pub use error::BufferError;
pub use ext::{u24, ReadExt, WriteExt};
use std::fmt::{Debug, Formatter};
use std::ops::{Range, RangeTo};
use std::{ptr, slice};

pub struct Buffer {
    buffer: Vec<u8>,
    offset: Range<usize>,
}

impl Default for Buffer {
    fn default() -> Self {
        Buffer::with_capacity(16437)
    }
}

impl Buffer {
    pub fn with_capacity(capacity: usize) -> Buffer {
        let buffer = vec![0u8; capacity];
        Buffer { buffer, offset: 0..0 }
    }

    pub fn new_bytes(bytes: Vec<u8>) -> Self {
        Buffer {
            offset: 0..bytes.len(),
            buffer: bytes,
        }
    }

    pub fn reset(&mut self) {
        self.offset = 0..0;
    }

    pub fn is_empty(&self) -> bool {
        self.offset.is_empty()
    }

    ///使用used字节后是否为空
    pub fn used_empty(&mut self, used: usize) -> bool {
        self.offset.start += used;
        self.is_empty()
    }

    pub fn len_ptr(&mut self) -> *mut usize {
        &mut self.offset.end
    }

    pub fn set_len(&mut self, len: usize) {
        self.offset.end = self.offset.start + len;
    }

    pub fn add_len(&mut self, len: usize) {
        self.offset.end += len;
    }

    pub fn starts_with(&self, bs: &[u8]) -> bool {
        self.buffer.starts_with(bs)
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.buffer[self.offset.clone()].to_vec()
    }

    pub fn capacity(&self) -> usize {
        self.buffer.capacity()
    }

    ///必须手动管理len, 返回已push的长度
    #[must_use]
    pub fn push_slice_in(&mut self, place: usize, slice: &[u8]) -> usize {
        unsafe {
            let dst = self.buffer.as_mut_ptr().add(place);
            ptr::copy_nonoverlapping(slice.as_ref().as_ptr(), dst, slice.len());
        }
        slice.len()
    }

    pub fn filled(&self) -> &[u8] {
        &self.buffer[self.offset.clone()]
    }

    pub fn filled_mut(&mut self) -> &mut [u8] {
        &mut self.buffer[self.offset.clone()]
    }

    pub fn unfilled_mut(&mut self) -> &mut [u8] {
        &mut self.buffer[self.offset.end..]
    }

    pub fn copy_within(&mut self, r: Range<usize>, pos: usize) {
        self.buffer.copy_within(r, pos);
    }

    pub fn move_to(&mut self, r: Range<usize>, pos: usize) {
        self.offset = pos..pos;
        self.offset.end += r.len();
        self.copy_within(r, pos);
    }

    pub fn drain(&mut self, range: RangeTo<usize>) -> Vec<u8> {
        let res = self.buffer[range].to_vec();
        self.copy_within(range.end..self.offset.end, 0);
        self.offset.end -= range.end;
        res
    }

    pub fn check_move(&mut self, size: usize, need: usize) -> Result<(), BufferError> {
        if self.unfilled_mut().len() < size && self.offset().start != 0 {
            self.move_to(self.offset(), 0);
        }
        if self.unfilled_mut().is_empty() {
            return Err(BufferError::CapacityTooSmall {
                needed: need,
                current: self.capacity(),
            });
        }
        Ok(())
    }
}

impl WriteExt for Buffer {
    fn as_ptr(&self) -> *const u8 {
        self.buffer.as_ptr()
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.buffer.as_mut_ptr()
    }

    fn add_len(&mut self, len: usize) {
        self.offset.end += len;
    }

    fn offset(&self) -> Range<usize> {
        self.offset.start..self.offset.end
    }

    fn capacity(&self) -> usize {
        self.buffer.capacity()
    }
}

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

    pub fn into_inner(self) -> &'a [u8] { self.buf }

    pub fn inner(&self) -> &'a [u8] { self.buf }
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
    fn size(&self) -> usize {
        self.buf.len()
    }

    fn position(&self) -> usize {
        self.pos
    }

    fn set_position(&mut self, pos: usize) {
        self.pos = pos;
    }

    fn add_len(&mut self, len: usize) {
        self.pos += len;
    }

    fn as_ptr(&self) -> *const u8 {
        self.buf.as_ptr()
    }
}