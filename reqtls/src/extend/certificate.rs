use std::fmt::{Debug, Formatter};
use crate::error::RlsResult;


pub struct CompressionType(u16);

impl CompressionType {
    pub const NULL: CompressionType = CompressionType(0);
    pub const DEFLATE: CompressionType = CompressionType(1);
    pub const BROTLI: CompressionType = CompressionType(2);
    pub fn new(value: u16) -> CompressionType {
        CompressionType(value)
    }

    pub fn as_bytes(&self) -> [u8; 2] {
        self.0.to_be_bytes()
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

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut res = vec![0];
        for ty in &self.types {
            res.extend(ty.as_bytes());
        }
        res[0] = (res.len() - 1) as u8;
        res
    }

    pub fn push(&mut self, ty: CompressionType) {
        self.types.push(ty);
    }
}



