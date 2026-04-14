use crate::error::RlsResult;
use crate::{BufferError, ReadExt, Reader, RlsError, WriteExt};

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
pub struct ServerName<'a> {
    list_len: u16,
    name_type: NameType,
    len: u16,
    value: &'a str,
}

impl<'a> ServerName<'a> {
    pub fn new() -> ServerName<'a> {
        ServerName {
            list_len: 0,
            name_type: NameType::HostName,
            len: 0,
            value: "",
        }
    }

    pub fn from_reader(mut reader: Reader<'a>) -> RlsResult<ServerName<'a>> {
        let mut res = ServerName::new();
        if reader.unread_len() == 0 { return Ok(res); }
        res.list_len = reader.read_u16()?;
        res.name_type = NameType::from_u8(reader.read_u8()?).ok_or("ServerName Unknown")?;
        res.len = reader.read_u16()?;
        res.value = reader.read_str::<RlsError>(res.len as usize)?;
        Ok(res)
    }

    pub fn len(&self) -> usize {
        5 + self.value.len()
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) -> Result<(), BufferError> {
        writer.write_u16(self.len() as u16 - 2)?;
        writer.write_u8(self.name_type as u8)?;
        writer.write_u16(self.value.len() as u16)?;
        writer.write_slice(self.value.as_ref())
    }

    pub fn set_value(&mut self, value: &'a str) {
        self.value = value;
        self.len = self.value.len() as u16;
    }

    pub fn value(&self) -> &str { &self.value }

    pub fn with_value(mut self, value: &'a str) -> ServerName<'a> {
        self.set_value(value);
        self
    }
}
