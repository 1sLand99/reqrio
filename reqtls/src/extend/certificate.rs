use std::fmt;
use std::fmt::{Debug, Display, Formatter};
use crate::error::RlsResult;
use crate::{BufferError, ReadExt, Reader, WriteExt};

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
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.0 {
            0 => write!(f, "Null(0)"),
            1 => write!(f, "Deflate(1)"),
            2 => write!(f, "Brotli(2)"),
            _ => write!(f, "Reserved({})", self.0),
        }
    }
}

impl Display for CompressionType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            CompressionType::DEFLATE => write!(f, "deflate"),
            CompressionType::BROTLI => write!(f, "br"),
            CompressionType::GZIP => write!(f, "gzip"),
            CompressionType::ZSTD => write!(f, "zstd"),
            _ => Err(fmt::Error),
        }
    }
}

#[derive(Debug)]
pub struct CompressionCertificate {
    methods: Vec<CompressionType>,
}

impl CompressionCertificate {
    pub fn new() -> CompressionCertificate {
        CompressionCertificate {
            methods: vec![],
        }
    }

    pub fn from_reader(mut reader: Reader<'_>) -> RlsResult<CompressionCertificate> {
        let len = reader.read_u8()?;
        let mut methods = Vec::with_capacity(reader.unread_len());
        for _ in (0..len).step_by(2) {
            methods.push(CompressionType::new(reader.read_u16()?));
        }
        Ok(CompressionCertificate {
            methods
        })
    }

    pub fn len(&self) -> usize {
        self.methods.len() * 2 + 1
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) -> Result<(), BufferError> {
        writer.write_u8(self.len() as u8 - 1)?;
        for ty in self.methods {
            writer.write_u16(ty.0)?;
        }
        Ok(())
    }

    pub fn push(&mut self, ty: CompressionType) {
        self.methods.push(ty);
    }
}



