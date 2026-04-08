use super::{DNSClass, DNSError, DNSValue, DnsType, Domain};
use crate::buffer::ReadExt;
use crate::Reader;

#[derive(Debug)]
pub struct Authoritative<'a> {
    name: Domain<'a>,
    type_: DnsType,
    class: DNSClass,
    live_sec: u32,
    data_len: u16,
    data: DNSValue<'a>,
}

impl<'a> Authoritative<'a> {
    pub fn from_bytes(reader: &'a Reader<'a>) -> Result<Authoritative<'a>, DNSError> {
        let name = Domain::from_bytes(reader)?;
        let type_ = DnsType(reader.read_u16()?);
        let class = DNSClass(reader.read_u16()?);
        let live_sec = reader.read_u32()?;
        let data_len = reader.read_u16()?;
        let data = DNSValue::from_bytes(&type_, reader,data_len as usize)?;

        Ok(Authoritative {
            name,
            type_,
            class,
            live_sec,
            data_len,
            data,
        })
    }
}