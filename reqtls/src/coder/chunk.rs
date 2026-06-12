use crate::coder::{CodingError, StreamDecode};
use crate::{ReadExt, Reader, WriteExt};
use std::cmp::min;
use std::marker::PhantomData;

pub struct ChunkDecoder<W: WriteExt, C: StreamDecode<W>> {
    coder: C,
    ///当前数据块需要的大小
    want_size: usize,
    ///当前数据块已读的大小
    read_size: usize,
    /// trim end
    trim_end: bool,
    _marker: PhantomData<W>,
    finish: bool,
}

impl<W: WriteExt, C: StreamDecode<W>> ChunkDecoder<W, C> {
    pub fn new(coder: C) -> Self {
        ChunkDecoder {
            coder,
            want_size: 0,
            read_size: 0,
            trim_end: true,
            _marker: PhantomData,
            finish: false,
        }
    }

    pub fn finish(&self) -> bool { self.finish }

    fn handle_decomp(&mut self, except: usize, reader: &mut Reader<'_>, out: &mut W) -> Result<bool, CodingError> {
        let pos = reader.position();
        let mut chunk_reader = reader.read_reader(min(except, reader.unread_len()))?;
        let ret = self.coder.decompress(&mut chunk_reader, out);
        self.read_size += chunk_reader.position();
        reader.set_position(pos + chunk_reader.position());
        ret?;
        if chunk_reader.unread_len() == 0 && reader.unread_len() >= 2 {
            reader.add_len(2);
            self.trim_end = true;
        }
        Ok(self.read_size == self.want_size && self.trim_end)
    }

    fn handle_chunk<'a>(&mut self, reader: &mut Reader<'a>, out: &mut W) -> Result<(), CodingError> {
        while let Ok(len) = reader.read_to(b"\r\n") {
            self.finish = len == [48];
            let len = usize::from_str_radix(std::str::from_utf8(len)?, 16)?;
            self.want_size = len;
            self.read_size = 0;
            self.trim_end = false;
            reader.read_u16()?;
            if !self.handle_decomp(len, reader, out)? { break; }
        }
        Ok(())
    }
}

impl<W: WriteExt, C: StreamDecode<W>> StreamDecode<W> for ChunkDecoder<W, C> {
    fn decompress(&mut self, reader: &mut Reader<'_>, out: &mut W) -> Result<(), CodingError> {
        if self.want_size == self.read_size {
            if !self.trim_end {
                reader.read_u16()?;
                self.trim_end = true;
            }
        } else {
            let need = self.want_size - self.read_size;
            if !self.handle_decomp(need, reader, out)? { return Ok(()); }
        }
        self.handle_chunk(reader, out)
    }

    fn flush(&mut self, writer: &mut W) -> Result<(), CodingError> {
        self.coder.flush(writer)
    }

    fn finish(&self) -> bool {
        self.finish && self.trim_end
    }
}

#[cfg(test)]
mod chunk_tests {
    use crate::coder::chunk::ChunkDecoder;
    use crate::coder::{DeflateStream, StreamDecode};
    use crate::{Buffer, Reader};
    use std::fs;

    #[test]
    fn test_chunk_decode() {
        let mut decoder = ChunkDecoder::new(());
        let context = b"10\r\nfjksdfhjdsfjdskj\r\n0\r\n\r\n";
        let mut out = Buffer::with_capacity(1024);
        decoder.decompress(&mut Reader::from_slice(context), &mut out).unwrap();
        assert_eq!(out.filled(), b"fjksdfhjdsfjdskj");
        assert!(decoder.finish);
    }

    #[test]
    fn test_chunk_gzip() {
        let data = fs::read("../data/coder/chunk_gzip.bin").unwrap();
        let mut decompressed = Buffer::with_capacity(data.len() * 10);
        let mut decoder = ChunkDecoder::new(DeflateStream::new_decompress(DeflateStream::GZIP).unwrap());
        decoder.decompress(&mut Reader::from_slice(&data), &mut decompressed).unwrap();
        // println!("{:?}", decompressed.filled());
        assert!(std::str::from_utf8(decompressed.filled()).is_ok())
    }
}