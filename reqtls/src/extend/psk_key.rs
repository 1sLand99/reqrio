use crate::error::RlsResult;
use crate::{BufferError, ReadExt, Reader, WriteExt};

#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum PskKeyType {
    PSK_DHE_KE = 0x1
}

impl PskKeyType {
    pub fn from_u8(value: u8) -> Option<PskKeyType> {
        match value {
            0x1 => Some(PskKeyType::PSK_DHE_KE),
            _ => None
        }
    }
}

#[derive(Debug)]
pub struct PskKey {
    mode: PskKeyType,
}

impl PskKey {
    pub fn new() -> PskKey {
        PskKey {
            mode: PskKeyType::PSK_DHE_KE,
        }
    }

    pub fn from_reader(mut reader: Reader<'_>) -> RlsResult<Self> {
        reader.read_u8()?;
        Ok(PskKey {
            mode: PskKeyType::from_u8(reader.read_u8()?).ok_or("PskKeyType Unknown")?,
        })
    }

    pub fn len(&self) -> usize { 2 }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) -> Result<(), BufferError> {
        writer.write_u8(self.len() as u8 - 1)?;
        writer.write_u8(self.mode as u8)
    }
}