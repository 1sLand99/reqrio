use crate::error::HlsResult;
use reqtls::WriteExt;
use std::ops::Range;

pub struct Reader<'a> {
    buffer: &'a mut [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self { buffer, pos: 0 }
    }

    pub fn filled(&self) -> &[u8] { &self.buffer[..self.pos] }

    pub fn unfilled_len(&self) -> usize { self.buffer.len() - self.pos }

    pub fn unfilled(&mut self) -> &mut [u8] { &mut self.buffer[self.pos..] }

    pub fn capacity(&self) -> usize { self.buffer.len() }

    pub fn is_empty(&self) -> bool {
        self.pos >= self.buffer.len()
    }
}

impl<'a> WriteExt for Reader<'a> {
    fn as_ptr(&self) -> *const u8 {
        self.buffer.as_ptr()
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.buffer.as_mut_ptr()
    }

    fn add_len(&mut self, len: usize) {
        self.pos += len
    }

    fn offset(&self) -> Range<usize> {
        0..self.pos
    }
}


pub trait ReadExt {
    fn read(&mut self, buf: &mut Reader) -> HlsResult<usize>;
}