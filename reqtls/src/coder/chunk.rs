use std::cmp::min;
use crate::coder::StreamDecode;
use crate::{ReadExt, Reader, RlsError, WriteExt};
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
            _marker: PhantomData::default(),
            finish: false,
        }
    }

    pub fn finish(&self) -> bool { self.finish }

    fn handle_chunk<'a>(&mut self, reader: &mut Reader<'a>, out: &mut W) -> Result<usize, RlsError>
    where
        RlsError: From<C::Error>,
    {
        while let Ok(len) = reader.read_to(b"\r\n") {
            if len == [48] {
                reader.add_len(2);
                self.finish = true;
                return Ok(reader.unread_len());
            }
            let len = usize::from_str_radix(std::str::from_utf8(len)?, 16)?;
            self.want_size = len;
            self.read_size = 0;
            self.trim_end = false;
            reader.add_len(2);
            if reader.unread_len() >= len {
                self.coder.decompress(reader.read_reader(len)?, out)?;
                self.read_size = len;
                if reader.unread_len() > 2 {
                    reader.add_len(2);
                    self.trim_end = true;
                }
            } else {
                self.read_size = reader.unread_len();
                self.coder.decompress(reader.read_reader(reader.unread_len())?, out)?;
            }
        }
        Ok(reader.unread_len())
    }
}

impl<W: WriteExt, C: StreamDecode<W>> StreamDecode<W> for ChunkDecoder<W, C>
where
    RlsError: From<C::Error>,
{
    type Error = RlsError;

    fn decompress(&mut self, mut reader: Reader<'_>, out: &mut W) -> Result<usize, Self::Error> {
        if self.want_size == self.read_size {
            self.handle_chunk(&mut reader, out)
        } else {
            let need = self.want_size - self.read_size;
            if reader.unread_len() <= need + 2 {
                let read = min(reader.unread_len(), need);
                self.coder.decompress(reader.read_reader(read).unwrap(), out)?;
                self.read_size += read;
                if reader.unread_len() >= 2 {
                    reader.add_len(2);
                    self.trim_end = true;
                }
                Ok(0)
            } else {
                self.coder.decompress(reader.read_reader(need).unwrap(), out)?;
                self.read_size += need;
                reader.read_slice(2)?;
                self.trim_end = true;
                self.handle_chunk(&mut reader, out)
            }
        }
    }
}

#[cfg(test)]
mod chunk_tests {
    use crate::coder::chunk::ChunkDecoder;
    use crate::coder::StreamDecode;
    use crate::{Buffer, ReadExt, Reader};

    #[test]
    fn test_chunk_decode() {
        let mut decoder = ChunkDecoder::new(());
        let context = b"10\r\nfjksdfhjdsfjdskj\r\n0\r\n";
        let mut out = Buffer::with_capacity(1024);
        let unread = decoder.decompress(Reader::from_slice(context), &mut out).unwrap();
        assert_eq!(out.filled(), b"fjksdfhjdsfjdskj");
        assert!(decoder.finish);
        assert_eq!(unread, 0);

        let mut decoder = ChunkDecoder::new(());
        out.reset();
        let mut reader = Reader::from_slice(context);
        let unread = decoder.decompress(reader.read_reader(4).unwrap(), &mut out).unwrap();
        assert_eq!(unread, 0);
        let unread = decoder.decompress(reader.read_reader(3).unwrap(), &mut out).unwrap();
        assert_eq!(unread, 0);
        let unread = decoder.decompress(reader.read_reader(3).unwrap(), &mut out).unwrap();
        assert_eq!(unread, 0);
        let unread = decoder.decompress(reader.read_reader(3).unwrap(), &mut out).unwrap();
        assert_eq!(unread, 0);
        let unread = decoder.decompress(reader.read_reader(3).unwrap(), &mut out).unwrap();
        assert_eq!(unread, 0);
        let unread = decoder.decompress(reader.read_reader(3).unwrap(), &mut out).unwrap();
        assert_eq!(unread, 0);
        let unread = decoder.decompress(reader.read_reader(3).unwrap(), &mut out).unwrap();
        assert_eq!(unread, 0);
        let unread = decoder.decompress(reader.read_reader(3).unwrap(), &mut out).unwrap();
        assert_eq!(unread, 0);
    }
}