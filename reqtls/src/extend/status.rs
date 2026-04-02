use crate::error::RlsResult;
use crate::{BufferError, WriteExt};

#[derive(Debug, Copy, Clone)]
pub enum StatusType {
    OCSP = 0x1
}

impl StatusType {
    pub fn from_u8(value: u8) -> Option<StatusType> {
        match value {
            0x1 => Some(StatusType::OCSP),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct StatusRequest {
    status_type: StatusType,
    responder_id_len: u16,
    request_extend_len: u16,
}

impl StatusRequest {
    pub fn new() -> StatusRequest {
        StatusRequest {
            status_type: StatusType::OCSP,
            responder_id_len: 0,
            request_extend_len: 0,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> RlsResult<StatusRequest> {
        let mut res = StatusRequest::new();
        if bytes.len() == 0 { return Ok(res); }
        res.status_type = StatusType::from_u8(bytes[0]).ok_or("Status Type Unknown")?;
        res.responder_id_len = u16::from_be_bytes([bytes[1], bytes[2]]);
        res.request_extend_len = u16::from_be_bytes([bytes[3], bytes[4]]);
        Ok(res)
    }

    pub fn len(&self) -> usize {
        5
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) -> Result<(), BufferError> {
        writer.write_u8(self.status_type as u8)?;
        writer.write_u16(self.responder_id_len)?;
        writer.write_u16(self.request_extend_len)
    }
}