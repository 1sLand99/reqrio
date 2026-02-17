use std::ffi::CString;
use crate::error::RlsResult;
use crate::{ext, WriteExt};

#[derive(Debug, Clone, Copy)]
pub enum NameType {
    HostName = 0x0
}

impl NameType {
    pub fn from_u8(v: u8) -> Option<NameType> {
        match v {
            0x0 => Some(NameType::HostName),
            _ => None
        }
    }
}

#[derive(Debug)]
pub struct ServerName {
    list_len: u16,
    name_type: NameType,
    len: u16,
    value: String,
}

impl ServerName {
    pub fn new() -> ServerName {
        ServerName {
            list_len: 0,
            name_type: NameType::HostName,
            len: 0,
            value: "".to_string(),
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> RlsResult<ServerName> {
        let mut res = ServerName::new();
        if bytes.is_empty() { return Ok(res); }
        res.list_len = u16::from_be_bytes([bytes[0], bytes[1]]);
        res.name_type = NameType::from_u8(bytes[2]).ok_or("ServerName Unknown")?;
        res.len = u16::from_be_bytes([bytes[3], bytes[4]]);
        res.value = String::from_utf8(bytes[5..res.len as usize + 5].to_vec())?;
        Ok(res)
    }

    pub fn len(&self) -> usize {
        5 + self.value.len()
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) {
        writer.write_u16(self.len() as u16 - 2);
        writer.write_u8(self.name_type as u8);
        writer.write_u16(self.value.len() as u16);
        if let Ok(sni) = CString::new(self.value.as_str()) {
            unsafe { ext::set_sni(writer.offset().start, sni.as_ptr(), self.value.len()) }
        }
        writer.write_slice(self.value.as_ref())
    }

    pub fn set_value(&mut self, value: impl ToString) {
        self.value = value.to_string();
        self.len = self.value.len() as u16;
    }

    pub fn value(&self) -> &str { &self.value }
}
