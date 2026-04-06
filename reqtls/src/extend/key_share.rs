use crate::buffer::Buf;
use crate::{BufferError, WriteExt};
use std::fmt::{Debug, Formatter};

#[derive(PartialEq)]
pub struct KeyShareType(u16);

impl KeyShareType {
    pub const X25519MLKEM768: KeyShareType = KeyShareType(0x11ec);
    pub const X25519: KeyShareType = KeyShareType(0x001d);
    pub fn new(v: u16) -> Self {
        KeyShareType(v)
    }

    pub fn into_inner(self) -> u16 { self.0 }

    pub fn spec(&self) -> &str {
        match *self {
            KeyShareType::X25519MLKEM768 => "X25519MLKEM768",
            KeyShareType::X25519 => "X25519",
            _ => "Reserved",
        }
    }
}

impl Debug for KeyShareType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}({:x})", self.spec(), self.0)
    }
}

#[derive(Debug)]
pub struct KeyShareEntry<'a> {
    group: KeyShareType,
    exchange_len: u16,
    exchange: Buf<'a>,
}

impl<'a> KeyShareEntry<'a> {
    fn new() -> KeyShareEntry<'a> {
        KeyShareEntry {
            group: KeyShareType(0),
            exchange_len: 0,
            exchange: Buf::Ref(&[]),
        }
    }

    fn from_bytes(bytes: &[u8]) -> Vec<KeyShareEntry<'_>> {
        let mut index = 0;
        let mut res = vec![];
        while index < bytes.len() {
            let mut key = KeyShareEntry::new();
            key.group = KeyShareType::new(u16::from_be_bytes([bytes[index], bytes[index + 1]]));
            key.exchange_len = u16::from_be_bytes([bytes[index + 2], bytes[index + 3]]);
            index = index + 4 + key.exchange_len as usize;
            key.exchange = Buf::Ref(&bytes[index - key.exchange_len as usize..index]);
            res.push(key);
        }
        res
    }

    pub fn len(&self) -> usize {
        4 + self.exchange.len()
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) -> Result<(), BufferError> {
        writer.write_u16(self.group.into_inner())?;
        writer.write_u16(self.exchange.len() as u16)?;
        writer.write_slice(self.exchange.as_ref())
    }
}

#[derive(Debug)]
pub struct KeyShare<'a> {
    len: u16,
    entries: Vec<KeyShareEntry<'a>>,
}

impl<'a> KeyShare<'a> {
    pub fn new() -> KeyShare<'a> {
        KeyShare {
            len: 0,
            entries: vec![],
        }
    }
    pub fn from_bytes(bytes: &[u8]) -> KeyShare<'_> {
        let mut res = KeyShare::new();
        res.len = u16::from_be_bytes([bytes[0], bytes[1]]);
        res.entries = KeyShareEntry::from_bytes(&bytes[2..res.len as usize + 2]);
        res
    }

    pub fn len(&self) -> usize {
        self.entries.iter().map(|x| x.len()).sum::<usize>() + 2
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) -> Result<(), BufferError> {
        writer.write_u16(self.len() as u16 - 2)?;
        for entry in self.entries {
            entry.write_to(writer)?;
        }
        Ok(())
    }
}

