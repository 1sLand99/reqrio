use reqtls::WriteExt;
use crate::Buffer;
use crate::error::HlsResult;

pub struct BufReader<R: AsRef<[u8]>> {
    inner: R,
    pos: usize,
}

impl<R: AsRef<[u8]>> BufReader<R> {
    pub fn new(inner: R) -> Self {
        Self { inner, pos: 0 }
    }

    // pub fn as_slice(&self) -> &[u8] { &self.inner.as_ref()[self.pos..] }

    // pub fn is_empty(&self) -> bool { self.pos >= self.as_slice().len() }

    pub fn len(&self) -> usize { self.inner.as_ref().len() - self.pos }
}

impl<R: AsRef<[u8]>> ReadExt for BufReader<R> {
    fn read(&mut self, buf: &mut Buffer) -> HlsResult<usize> {
        let inner = self.inner.as_ref();
        let remain = inner.len() - self.pos;
        let want_size = buf.unfilled_mut().len();
        match remain > buf.unfilled_mut().len() {
            true => {
                buf.write_slice(&inner[self.pos..self.pos + want_size]);
                self.pos += want_size;
                Ok(want_size)
            }
            false => {
                buf.write_slice(&inner[self.pos..self.pos + remain]);
                self.pos += remain;
                Ok(remain)
            }
        }
    }
}

pub trait ReadExt {
    fn read(&mut self, buf: &mut Buffer) -> HlsResult<usize>;
}