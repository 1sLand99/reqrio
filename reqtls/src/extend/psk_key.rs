use crate::error::RlsResult;
use crate::WriteExt;

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
    len: u8,
    mode: PskKeyType,
}

impl PskKey {
    pub fn new() -> PskKey {
        PskKey {
            len: 0,
            mode: PskKeyType::PSK_DHE_KE,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> RlsResult<Self> {
        let mut res = PskKey::new();
        res.len = bytes[0];
        res.mode = PskKeyType::from_u8(bytes[1]).ok_or("PskKeyType Unknown")?;
        Ok(res)
    }

    pub fn len(&self) -> usize { 2 }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) {
        writer.write_u8(self.len() as u8 - 1);
        writer.write_u8(self.mode as u8)
    }
}