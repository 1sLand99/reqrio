use std::fmt::{Debug, Formatter};
use crate::error::RlsResult;
use crate::WriteExt;

#[derive(PartialEq)]
pub struct CompressionType(u16);

impl CompressionType {
    pub const NULL: CompressionType = CompressionType(0);
    pub const DEFLATE: CompressionType = CompressionType(1);
    pub const BROTLI: CompressionType = CompressionType(2);
    pub const GZIP: CompressionType = CompressionType(0xFFFF);
    pub const ZSTD: CompressionType = CompressionType(0xFFFE);
    pub fn new(value: u16) -> CompressionType {
        CompressionType(value)
    }

    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> CompressionType {
        match bytes.as_ref() {
            b"deflate" => CompressionType::DEFLATE,
            b"br" => CompressionType::BROTLI,
            b"gzip" => CompressionType::GZIP,
            b"zstd" => CompressionType::ZSTD,
            _ => CompressionType::NULL
        }
    }
}


impl Debug for CompressionType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            0 => write!(f, "Null(0)"),
            1 => write!(f, "Deflate(1)"),
            2 => write!(f, "Brotli(2)"),
            _ => write!(f, "Reserved({})", self.0),
        }
    }
}

#[derive(Debug)]
pub struct CompressionCertificate {
    len: u8,
    types: Vec<CompressionType>,
}

impl CompressionCertificate {
    pub fn new() -> CompressionCertificate {
        CompressionCertificate {
            len: 0,
            types: vec![],
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> RlsResult<CompressionCertificate> {
        let mut res = CompressionCertificate::new();
        res.len = bytes[0];
        let mut index = 1;
        while index < bytes.len() {
            let v = u16::from_be_bytes([bytes[index], bytes[index + 1]]);
            res.types.push(CompressionType(v));
            index += 2;
        }

        Ok(res)
    }

    pub fn len(&self) -> usize {
        self.types.len() * 2 + 1
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) {
        writer.write_u8(self.len() as u8 - 1);
        for ty in self.types {
            writer.write_u16(ty.0);
        }
    }
    
    pub fn push(&mut self, ty: CompressionType) {
        self.types.push(ty);
    }
}



