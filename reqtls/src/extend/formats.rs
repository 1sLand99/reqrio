use std::fmt::{Debug, Formatter};
use crate::error::RlsResult;
use crate::WriteExt;

#[allow(non_camel_case_types)]
#[derive(Clone, PartialEq)]
pub struct EcPointFormat(u8);

impl EcPointFormat {
    pub const UNCOMPRESSED: EcPointFormat = EcPointFormat(0x0);
    pub const ANSI_X962_PRIME: EcPointFormat = EcPointFormat(0x1);
    pub const ANSI_X962_CHAR2: EcPointFormat = EcPointFormat(0x2);

    pub fn spec(&self) -> &str {
        match *self {
            EcPointFormat::UNCOMPRESSED => "UNCOMPRESSED",
            EcPointFormat::ANSI_X962_PRIME => "ANSI_X962_PRIME",
            EcPointFormat::ANSI_X962_CHAR2 => "ANSI_X962_CHAR2",
            _ => "Reserved"
        }
    }
    pub fn into_inner(self) -> u8 {
        self.0
    }

    pub fn new(v: u8) -> EcPointFormat {
        EcPointFormat(v)
    }
}

impl Debug for EcPointFormat {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}(0x{:x})", self.spec(), self.0)
    }
}

#[derive(Debug)]
pub struct EcPointFormats {
    len: u8,
    formats: Vec<EcPointFormat>,
}

impl EcPointFormats {
    pub fn new() -> EcPointFormats {
        EcPointFormats {
            len: 0,
            formats: vec![],
        }
    }

    pub fn random() -> EcPointFormats {
        let mut res = EcPointFormats::new();
        res.formats = vec![EcPointFormat::UNCOMPRESSED];
        res
    }

    pub fn from_bytes(bytes: &[u8]) -> RlsResult<EcPointFormats> {
        let mut res = EcPointFormats::new();
        res.len = bytes[0];
        for v in &bytes[1..] {
            res.formats.push(EcPointFormat::new(*v));
        }
        Ok(res)
    }

    pub fn len(&self) -> usize { self.formats.len() + 1 }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) {
        writer.write_u8(self.len() as u8 - 1);
        for format in self.formats {
            writer.write_u8(format.into_inner());
        }
    }

    pub fn clear(&mut self) {
        self.formats.clear();
    }

    pub fn add_format(&mut self, format: EcPointFormat) {
        self.formats.push(format);
    }

    pub fn formats(&self) -> &Vec<EcPointFormat> {
        &self.formats
    }
}