use crate::error::RlsResult;
use crate::WriteExt;

#[allow(non_camel_case_types)]
#[derive(Debug, Clone)]
pub enum EcPointFormat {
    UNCOMPRESSED = 0x0,
    ANSI_X962_PRIME = 0x1,
    ANSI_X962_CHAR2 = 0x2,
}

impl EcPointFormat {
    pub fn from_u8(v: u8) -> Option<EcPointFormat> {
        match v {
            0x0 => Some(EcPointFormat::UNCOMPRESSED),
            0x1 => Some(EcPointFormat::ANSI_X962_PRIME),
            0x2 => Some(EcPointFormat::ANSI_X962_CHAR2),
            _ => None,
        }
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
            res.formats.push(EcPointFormat::from_u8(*v).ok_or("EcPointFormat Unknown")?);
        }
        Ok(res)
    }

    pub fn len(&self) -> usize { self.formats.len() + 1 }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) {
        writer.write_u8(self.len() as u8 - 1);
        for format in self.formats {
            writer.write_u8(format as u8);
        }
    }

    pub fn add_format(&mut self, format: EcPointFormat) {
        self.formats.push(format);
    }

    pub fn formats(&self) -> &Vec<EcPointFormat> {
        &self.formats
    }
}