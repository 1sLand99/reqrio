use crate::buffer::ReadExt;
use crate::dns::error::DNSError;
use crate::dns::{DNSClass, DNSValue, DnsType, Domain};
use crate::Reader;
use std::fmt::Debug;

#[derive(Debug)]
struct AddZ {
    do_bit: u8,
    reserved: u16,
}

impl AddZ {
    pub fn from_u16(v: u16) -> AddZ {
        AddZ {
            do_bit: (v >> 15) as u8,
            reserved: v & 0x7FFF,
        }
    }
}

#[derive(Debug)]
struct AddOptionCode(u16);

impl AddOptionCode {
    const COOKIE: u16 = 0x000a;

    fn spec(&self) -> &str {
        match self.0 {
            AddOptionCode::COOKIE => "COOKIE",
            _ => "Reserved"
        }
    }
}

enum AddOption {
    Cookie(Vec<u8>),
    Reserved(Vec<u8>),
}

impl AddOption {
    fn from_bytes(bytes: &[u8]) -> AddOption {
        let code = AddOptionCode(u16::from_be_bytes([bytes[0], bytes[1]]));
        let len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        match code.0 {
            AddOptionCode::COOKIE => AddOption::Cookie(bytes[4..4 + len].to_vec()),
            _ => AddOption::Reserved(bytes[4..len].to_vec()),
        }
    }

    pub fn len(&self) -> usize {
        4 + match self {
            AddOption::Cookie(v) => v.len(),
            AddOption::Reserved(v) => v.len()
        }
    }
}

impl Debug for AddOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddOption::Cookie(v) => write!(f, "Cookie({})", hex::encode(v)),
            AddOption::Reserved(v) => write!(f, "Reserved({})", hex::encode(v)),
        }
    }
}

#[derive(Debug)]
pub struct Additional<'a> {
    name: Domain<'a>,
    type_: DnsType,
    class: DNSClass,
    live_sec: u32,
    data_len: u16,
    data: DNSValue<'a>,
}

impl<'a> Additional<'a> {
    pub fn from_bytes(reader: &'a Reader<'a>) -> Result<Additional<'a>, DNSError> {
        let name = Domain::from_bytes(reader)?;
        println!("{:?}", &reader[reader.position()..]);
        let type_: DnsType = reader.read_u16()?.into();
        let class: DNSClass = reader.read_u16()?.into();
        let live_sec = reader.read_u32()?;
        let data_len = reader.read_u16()?;
        let data = DNSValue::from_bytes(&type_, reader, data_len as usize)?;
        Ok(Additional {
            name,
            type_,
            class,
            live_sec,
            data_len,
            data,
        })
    }
}