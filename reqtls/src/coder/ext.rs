use crate::{BufferError, ReadExt, Reader, WriteExt};
use crate::coder::CodingError;

pub trait StreamDecode<W: WriteExt> {
    fn decompress(&mut self, reader: &mut Reader<'_>, out: &mut W) -> Result<(), CodingError>;
    fn flush(&mut self, out: &mut W) -> Result<(), CodingError>;
    fn finish(&self) -> bool;
}

pub trait StreamEncode {
    fn compress(&mut self, data: &[u8], out: &mut [u8]) -> Result<usize, CodingError>;
    fn finalize(&mut self, out: &mut [u8]) -> Result<usize, CodingError>;
}

impl<W: WriteExt> StreamDecode<W> for () {
    fn decompress(&mut self, reader: &mut Reader<'_>, out: &mut W) -> Result<(), CodingError> {
        out.write_slice(reader.read_slice(reader.unread_len())?)?;
        Ok(())
    }

    fn flush(&mut self, _: &mut W) -> Result<(), CodingError> { Ok(()) }

    fn finish(&self) -> bool {
        false
    }
}

impl StreamEncode for () {
    fn compress(&mut self, data: &[u8], out: &mut [u8]) -> Result<usize, CodingError> {
        if out.len() < data.len() {
            return Err(BufferError::CapacityTooSmall {
                current: out.len(),
                needed: data.len(),
            }.into());
        }
        out[..data.len()].copy_from_slice(data);
        Ok(data.len())
    }

    fn finalize(&mut self, _: &mut [u8]) -> Result<usize, CodingError> {
        Ok(0)
    }
}