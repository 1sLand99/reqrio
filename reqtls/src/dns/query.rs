use super::{DNSClass, DNSError, DnsType, Domain};
use crate::buffer::ReadExt;
use crate::Reader;
use std::fmt::Debug;


#[derive(Debug)]
pub struct DNSQuery<'a> {
    name: Domain<'a>,
    type_: DnsType,
    class: DNSClass,
}


impl<'a> DNSQuery<'a> {
    pub fn from_bytes<'b: 'a>(reader: &'b Reader<'a>) -> Result<DNSQuery<'a>, DNSError> {
        let name = Domain::from_bytes(reader)?;
        Ok(DNSQuery {
            name,
            type_: DnsType(reader.read_u16()?),
            class: DNSClass(reader.read_u16()?),
        })
    }
}
