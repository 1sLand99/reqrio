use crate::{BufferError, Reader, WriteExt};

pub trait StreamDecode<W: WriteExt> {
    type Error;
    fn decompress(&mut self, reader: Reader<'_>, out: &mut W) -> Result<usize, Self::Error>;
}

pub trait StreamEncode {
    type Error;
    fn compress(&mut self, data: &[u8], out: &mut [u8]) -> Result<usize, Self::Error>;
    fn flush(&mut self, out: &mut [u8]) -> Result<usize, Self::Error>;
}

impl<W: WriteExt> StreamDecode<W> for () {
    type Error = BufferError;

    fn decompress(&mut self, reader: Reader<'_>, out: &mut W) -> Result<usize, BufferError> {
        out.write_slice(reader.into_inner())?;
        Ok(0)
    }
}

impl StreamEncode for () {
    type Error = BufferError;
    fn compress(&mut self, data: &[u8], out: &mut [u8]) -> Result<usize, BufferError> {
        if out.len() < data.len() {
            return Err(BufferError::CapacityTooSmall {
                current: out.len(),
                needed: data.len(),
            });
        }
        out[..data.len()].copy_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self, _: &mut [u8]) -> Result<usize, BufferError> {
        Ok(0)
    }
}