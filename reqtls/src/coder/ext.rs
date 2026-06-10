use crate::{BufferError, ReadExt, Reader, WriteExt};

pub trait StreamDecode<W: WriteExt> {
    type Error;
    fn decompress(&mut self, reader: &mut Reader<'_>, out: &mut W) -> Result<(), Self::Error>;
}

pub trait StreamEncode {
    type Error;
    fn compress(&mut self, data: &[u8], out: &mut [u8]) -> Result<usize, Self::Error>;
    fn finalize(&mut self, out: &mut [u8]) -> Result<usize, Self::Error>;
}

impl<W: WriteExt> StreamDecode<W> for () {
    type Error = BufferError;

    fn decompress(&mut self, reader: &mut Reader<'_>, out: &mut W) -> Result<(), BufferError> {
        out.write_slice(reader.read_slice(reader.unread_len())?)?;
        Ok(())
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

    fn finalize(&mut self, _: &mut [u8]) -> Result<usize, BufferError> {
        Ok(0)
    }
}