use std::fmt::Debug;
use crate::dns::error::DNSError;

struct AdditionType(u16);

impl AdditionType {
    const OPT: u16 = 0x29;

    fn spec(&self) -> &str {
        match self.0 {
            AdditionType::OPT => "OPT",
            _ => "Reserved"
        }
    }
}

impl Debug for AdditionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}(0x{:x})", self.spec(), self.0)
    }
}

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
pub struct Additional {
    name: u8,
    type_: AdditionType,
    size: u16,
    rcode: u8,
    version: u8,
    z: AddZ,
    option: AddOption,
}

impl Additional {
    pub fn from_bytes(bytes: &[u8]) -> Result<Additional, DNSError> {
        let data_len = u16::from_be_bytes([bytes[9], bytes[10]]) as usize;
        Ok(Additional {
            name: bytes[0],
            type_: AdditionType(u16::from_be_bytes([bytes[1], bytes[2]])),
            size: u16::from_be_bytes([bytes[3], bytes[4]]),
            rcode: bytes[5],
            version: bytes[6],
            z: AddZ::from_u16(u16::from_be_bytes([bytes[7], bytes[8]])),
            option: AddOption::from_bytes(&bytes[11..11 + data_len]),
        })
    }
}