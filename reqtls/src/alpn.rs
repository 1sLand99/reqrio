use std::fmt::Display;
use crate::error::RlsResult;
use crate::WriteExt;

#[derive(Debug, PartialEq, Clone)]
pub enum ALPN {
    Http20,
    Http11,
    Http10,
    Custom(Vec<u8>),
}

impl ALPN {
    pub fn from_slice(opt: &[u8]) -> ALPN {
        match opt {
            b"http/1.0" => ALPN::Http10,
            b"http/1.1" => ALPN::Http11,
            b"h2" => ALPN::Http20,
            _ => ALPN::Custom(opt.to_vec()),
        }
    }

    pub fn value(&self) -> &str {
        match self {
            ALPN::Http10 => "http/1.0",
            ALPN::Http11 => "http/1.1",
            ALPN::Http20 => "h2",
            ALPN::Custom(v) => unsafe { std::str::from_utf8_unchecked(v.as_slice()) }
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> RlsResult<Vec<ALPN>> {
        let mut res = vec![];
        let mut index = 0;
        while index < bytes.len() {
            let len = bytes[index] as usize;
            res.push(ALPN::from_slice(&bytes[index + 1..len + index + 1]));
            index = index + 1 + len;
        }
        Ok(res)
    }

    pub fn is_empty(&self) -> bool { self.len() == 0 }

    pub fn len(&self) -> usize { 1 + self.value().len() }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) {
        writer.write_u8(self.value().len() as u8);
        writer.write_slice(self.value().as_bytes());
    }
}

impl Display for ALPN {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ALPN::Http20 => write!(f, "HTTP/2.0"),
            ALPN::Http11 => write!(f, "HTTP/1.1"),
            ALPN::Http10 => write!(f, "HTTP/1.0"),
            ALPN::Custom(v) => write!(f, "{}", String::from_utf8_lossy(v)),
        }
    }
}