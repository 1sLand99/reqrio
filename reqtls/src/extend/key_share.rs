use crate::buffer::Buf;
use crate::{BufferError, NamedCurve, WriteExt};
use std::fmt::Debug;

#[derive(Debug)]
pub struct KeyEntry<'a> {
    group: NamedCurve,
    exchange_len: u16,
    exchange: Buf<'a>,
}

impl<'a> KeyEntry<'a> {
    fn new() -> KeyEntry<'a> {
        KeyEntry {
            group: NamedCurve::new(0),
            exchange_len: 0,
            exchange: Buf::Ref(&[]),
        }
    }

    fn from_bytes(bytes: &[u8]) -> Vec<KeyEntry<'_>> {
        let mut index = 0;
        let mut res = vec![];
        while index < bytes.len() {
            let mut key = KeyEntry::new();
            key.group = u16::from_be_bytes([bytes[index], bytes[index + 1]]).into();
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

    pub fn name_curve(&self) -> NamedCurve {
        self.group
    }

    pub fn exchange_key(&self) -> &Buf<'_> {
        &self.exchange
    }
}

#[derive(Debug, Default)]
pub struct KeyShare<'a> {
    len: u16,
    entries: Vec<KeyEntry<'a>>,
}


impl<'a> KeyShare<'a> {
    pub fn from_bytes(bytes: &[u8], server: bool) -> KeyShare<'_> {
        // println!("{:x?}", bytes);
        let mut res = KeyShare::default();
        let offset = if !server {
            res.len = u16::from_be_bytes([bytes[0], bytes[1]]);
            2..res.len as usize + 2
        } else {
            0..bytes.len()
        };
        res.entries = KeyEntry::from_bytes(&bytes[offset]);
        res
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
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

    pub fn add_entry(&mut self, name_curve: impl Into<NamedCurve>, pub_key: Buf<'a>) {
        let entry = KeyEntry {
            group: name_curve.into(),
            exchange_len: 0,
            exchange: pub_key,
        };
        self.entries.push(entry);
    }

    pub fn key_entry(&self) -> &KeyEntry<'_> {
        &self.entries[0]
    }
}

