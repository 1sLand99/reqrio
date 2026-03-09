use std::io::{Cursor, Read};
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

pub struct RefReader<R> {
    bufs: Vec<Cursor<R>>,
    pos: usize,
    wrote: bool,
}

impl<R: AsRef<[u8]>> Default for RefReader<R> {
    fn default() -> Self {
        RefReader {
            bufs: vec![],
            pos: 0,
            wrote: false,
        }
    }
}

impl<R: AsRef<[u8]>> RefReader<R> {
    pub fn new_buf(buf: R) -> RefReader<R> {
        RefReader {
            bufs: vec![Cursor::new(buf)],
            pos: 0,
            wrote: false,
        }
    }
    pub fn add_buf(&mut self, buf: R) {
        self.bufs.push(Cursor::new(buf));
    }

    pub fn wrote(&self) -> bool { self.wrote }
}

impl<R: AsRef<[u8]>> ReadExt for RefReader<R> {
    fn wrote(&self) -> bool {
        self.wrote
    }
    fn read(&mut self, buf: &mut Reader) -> HlsResult<usize> {
        let start = buf.offset().end;
        for (index, reader) in self.bufs.iter_mut().enumerate() {
            if index < self.pos { continue; }
            loop {
                if buf.is_empty() { return Ok(buf.offset().end - start); }
                let len = reader.read(buf.unfilled())?;
                if len == 0 {
                    self.pos += 1;
                    break;
                }
                buf.add_len(len);
            }
        }
        self.wrote = true;
        Ok(buf.offset().end - start)
    }
}

pub trait ReadExt {
    fn wrote(&self) -> bool;
    fn read(&mut self, buf: &mut Reader) -> HlsResult<usize>;
}