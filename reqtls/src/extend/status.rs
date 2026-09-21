use std::fmt::Debug;
use crate::error::RlsResult;
use crate::{BufferError, Reader, Writer};

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct StatusType(u8);

impl StatusType {
    pub const OCSP: StatusType = StatusType::new(0x1);

    pub const fn new(value: u8) -> StatusType {
        StatusType(value)
    }
}

impl Debug for StatusType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            StatusType::OCSP => write!(f, "OCSP(0x{:02x})", self.0),
            _ => write!(f, "Unknown(0x{:02x})", self.0),
        }
    }
}

#[repr(C)]
#[derive(Clone)]
#[cfg_attr(debug_assertions, derive(Debug))]
pub struct StatusRequest {
    typ: StatusType,
    resp_id_len: u16,
    req_ext_len: u16,
}

impl Default for StatusRequest {
    fn default() -> Self {
        StatusRequest {
            typ: StatusType::OCSP,
            resp_id_len: 0,
            req_ext_len: 0,
        }
    }
}

impl StatusRequest {
    pub const OCSP: StatusRequest = StatusRequest { typ: StatusType::OCSP, resp_id_len: 0, req_ext_len: 0 };
    pub fn from_reader(mut reader: Reader<'_>) -> RlsResult<StatusRequest> {
        if reader.unread_len() == 0 { return Ok(StatusRequest::default()); }
        Ok(StatusRequest {
            typ: StatusType::new(reader.read_u8()?),
            resp_id_len: reader.read_u16()?,
            req_ext_len: reader.read_u16()?,
        })
    }

    pub fn len(&self) -> usize {
        5
    }

    pub fn write_to(self, writer: &mut Writer) -> Result<(), BufferError> {
        writer.write_u8(self.typ.0)?;
        writer.write_u16(self.resp_id_len)?;
        writer.write_u16(self.req_ext_len)
    }
}