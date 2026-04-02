use crate::bytes::Bytes;
use crate::error::RlsResult;
use crate::{rand, BufferError, WriteExt};

#[derive(Debug)]
pub struct PskIdentity {
    len: u16,
    value: Bytes,
    age: u32,
}

impl PskIdentity {
    fn new() -> PskIdentity {
        PskIdentity {
            len: 0,
            value: Bytes::none(),
            age: 0,
        }
    }

    fn random() -> PskIdentity {
        let mut res = PskIdentity::new();
        res.value = Bytes::new(rand::random::<[u8; 140]>().to_vec());
        res.age = rand::random();
        res
    }

    fn from_bytes(bytes: &[u8]) -> RlsResult<PskIdentity> {
        let mut res = PskIdentity::new();
        res.len = u16::from_be_bytes([bytes[0], bytes[1]]);
        res.value = Bytes::new(bytes[2..2 + res.len as usize].to_vec());
        res.age = u32::from_be_bytes(bytes[2 + res.len as usize..].try_into()?);
        Ok(res)
    }

    pub fn len(&self) -> usize {
        6 + self.value.len()
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) -> Result<(), BufferError> {
        writer.write_u16(self.value.len() as u16)?;
        writer.write_slice(self.value.as_ref())?;
        writer.write_u32(self.age, false)
    }
}

#[derive(Debug)]
pub struct PskBinder {
    len: u8,
    value: Bytes,
}

impl PskBinder {
    fn new() -> PskBinder {
        PskBinder {
            len: 0,
            value: Bytes::none(),
        }
    }

    fn random() -> PskBinder {
        let mut res = PskBinder::new();
        res.value = Bytes::new(rand::random::<[u8; 48]>().to_vec());
        res
    }

    fn from_bytes(bytes: &[u8]) -> RlsResult<PskBinder> {
        let mut res = PskBinder::new();
        res.len = bytes[0];
        res.value = Bytes::new(bytes[1..1 + res.len as usize].to_vec());
        Ok(res)
    }

    pub fn len(&self) -> usize {
        1 + self.value.len()
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) -> Result<(), BufferError> {
        writer.write_u8(self.value.len() as u8)?;
        writer.write_slice(self.value.as_ref())
    }
}

#[derive(Debug)]
pub struct PreSharedKey {
    identity_len: u16,
    identity: PskIdentity,
    binder_len: u16,
    binder: PskBinder,

}

impl PreSharedKey {
    pub fn new() -> PreSharedKey {
        PreSharedKey {
            identity_len: 0,
            identity: PskIdentity::new(),
            binder_len: 0,
            binder: PskBinder::new(),
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> RlsResult<PreSharedKey> {
        let mut res = PreSharedKey::new();
        res.identity_len = u16::from_be_bytes([bytes[0], bytes[1]]);
        res.identity = PskIdentity::from_bytes(&bytes[2..2 + res.identity_len as usize])?;
        let index = 2 + res.identity_len as usize;
        res.binder_len = u16::from_be_bytes([bytes[index], bytes[index + 1]]);
        res.binder = PskBinder::from_bytes(&bytes[index + 2..index + 2 + res.binder_len as usize])?;
        Ok(res)
    }

    pub fn random() -> PreSharedKey {
        let mut res = PreSharedKey::new();
        res.identity = PskIdentity::random();
        res.binder = PskBinder::random();
        res
    }

    pub fn len(&self) -> usize {
        4 + self.binder.len() + self.identity.len()
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) -> Result<(), BufferError> {
        writer.write_u16(self.identity.len() as u16)?;
        self.identity.write_to(writer)?;
        writer.write_u16(self.binder.len() as u16)?;
        self.binder.write_to(writer)
    }
}