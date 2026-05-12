use std::fmt::Debug;
use crate::error::RlsResult;
use crate::{BufferError, ReadExt, Reader, WriteExt};

#[derive(Copy, Clone)]
pub struct PskMode(u8);

impl PskMode {
    pub const PSK_DHE_KE: PskMode = PskMode(0x1);
    pub fn new(value: u8) -> PskMode { PskMode(value) }

    pub fn into_inner(self) -> u8 { self.0 }

    fn spec(&self) -> &str {
        match self.0 {
            0x1 => "PSK_DHE_KE",
            _ => "Reserved"
        }
    }
}

impl Debug for PskMode {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}(0x{:02x})", self.spec(), self.0)
    }
}

impl From<u8> for PskMode {
    fn from(value: u8) -> PskMode {
        PskMode(value)
    }
}

#[derive(Debug)]
pub struct PskKey {
    mode: PskMode,
}

impl PskKey {
    pub fn new() -> PskKey {
        PskKey {
            mode: PskMode::PSK_DHE_KE,
        }
    }

    pub fn from_reader(mut reader: Reader<'_>) -> RlsResult<Self> {
        reader.read_u8()?;
        Ok(PskKey {
            mode: PskMode::new(reader.read_u8()?),
        })
    }

    pub fn len(&self) -> usize { 2 }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) -> Result<(), BufferError> {
        writer.write_u8(self.len() as u8 - 1)?;
        writer.write_u8(self.mode.into_inner())
    }

    pub fn set_mode(&mut self, mode: PskMode) {
        self.mode = mode;
    }
}