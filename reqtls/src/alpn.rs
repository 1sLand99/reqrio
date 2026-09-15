use crate::error::RlsResult;
use crate::{BufferError, Reader, Writer};
use std::fmt::Display;

#[repr(C)]
#[derive(Default, PartialEq, Clone)]
pub struct ALPN {
    len: u8,
    ptr: [u8; 15],
}

impl ALPN {
    pub const HTTP11: ALPN = ALPN { len: 8, ptr: [104, 116, 116, 112, 47, 49, 46, 49, 0, 0, 0, 0, 0, 0, 0] };
    pub const HTTP20: ALPN = ALPN { len: 2, ptr: [104, 50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] };
    #[cfg(feature = "quic")]
    pub const HTTP30: ALPN = ALPN { len: 2, ptr: [104, 51, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] };

    pub fn from_slice(opt: &[u8]) -> ALPN {
        let mut res = ALPN::default();
        res.len = opt.len() as u8;
        res.ptr[..opt.len()].copy_from_slice(opt);
        res
    }

    pub fn value(&self) -> &str {
        unsafe { std::str::from_utf8_unchecked(&self.ptr[..self.len as usize]) }
    }

    pub fn from_reader(reader: &mut Reader<'_>) -> RlsResult<Vec<ALPN>> {
        let mut res = Vec::with_capacity(reader.unread_len());
        while reader.unread_len() > 0 {
            let len = reader.read_u8()?;
            res.push(ALPN::from_slice(reader.read_slice(len as usize)?));
        }
        Ok(res)
    }

    pub fn is_empty(&self) -> bool { self.len() == 0 }

    pub fn len(&self) -> usize { 1 + self.len as usize }

    pub fn write_to(self, writer: &mut Writer) -> Result<(), BufferError> {
        writer.write_u8(self.len)?;
        writer.write_slice(&self.ptr[..self.len as usize])
    }
}

impl Display for ALPN {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            #[cfg(feature = "quic")]
            ALPN::HTTP30 => write!(f, "HTTP/3.0"),
            ALPN::HTTP20 => write!(f, "HTTP/2.0"),
            ALPN::HTTP11 => write!(f, "HTTP/1.1"),
            _ => write!(f, "{}", String::from_utf8_lossy(&self.ptr[..self.len as usize]).to_uppercase()),
        }
    }
}

#[cfg(debug_assertions)]
impl std::fmt::Debug for ALPN {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}