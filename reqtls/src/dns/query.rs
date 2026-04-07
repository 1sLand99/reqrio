use std::fmt::Debug;
use crate::dns::error::DNSError;

struct QueryType(u16);

impl QueryType {
    const HTTPS: u16 = 0x0041;

    fn spec(&self) -> &str {
        match self.0 {
            QueryType::HTTPS => "HTTPS",
            _ => "Reserved"
        }
    }
}

impl Debug for QueryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}(0x{:x})", self.spec(), self.0)
    }
}

struct QueryClass(u16);

impl QueryClass {
    const IN: u16 = 0x0001;

    fn spec(&self) -> &str {
        match self.0 {
            QueryClass::IN => "IN",
            _ => "Reserved"
        }
    }
}

impl Debug for QueryClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}(0x{:x})", self.spec(), self.0)
    }
}

#[derive(Debug)]
pub struct DNSQuery {
    name: String,
    type_: QueryType,
    class: QueryClass,
}


impl DNSQuery {
    pub fn len(&self) -> usize {
        self.name.len() + 6
    }
    pub fn from_bytes(mut bytes: &[u8]) -> Result<DNSQuery, DNSError> {
        let mut names = vec![];
        while bytes[0] != 0 {
            let len = bytes[0] as usize;
            names.push(std::str::from_utf8(&bytes[1..1 + len]).map_err(|e| DNSError::InvalidName(e))?);
            let (_, remain) = bytes.split_at(len + 1);
            bytes = remain;
        }
        Ok(DNSQuery {
            name: names.join("."),
            type_: QueryType(u16::from_be_bytes([bytes[1], bytes[2]])),
            class: QueryClass(u16::from_be_bytes([bytes[3], bytes[4]])),
        })
    }
}