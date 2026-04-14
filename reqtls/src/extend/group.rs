use crate::error::RlsResult;
use crate::{BufferError, NamedCurve, WriteExt};
use std::fmt::Debug;


#[derive(Debug)]
pub struct SupportedGroups {
    len: u16,
    values: Vec<NamedCurve>,
}

impl SupportedGroups {
    pub fn new() -> SupportedGroups {
        SupportedGroups {
            len: 0,
            values: vec![],
        }
    }
    pub fn from_bytes(bytes: &[u8]) -> RlsResult<SupportedGroups> {
        let mut res = SupportedGroups::new();
        res.len = u16::from_be_bytes([bytes[0], bytes[1]]);
        for chuck in bytes[2..].chunks(2) {
            let v = u16::from_be_bytes(chuck.try_into()?);
            res.values.push(NamedCurve::new(v));
        }
        Ok(res)
    }

    pub fn len(&self) -> usize {
        self.values.len() * 2 + 2
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) -> Result<(), BufferError> {
        writer.write_u16(self.len() as u16 - 2)?;
        for value in self.values {
            writer.write_u16(value.into_inner())?;
        }
        Ok(())
    }

    pub fn clear(&mut self) {
        self.values.clear();
    }

    pub fn set_values(&mut self, values: Vec<NamedCurve>) {
        self.values = values;
    }
    pub fn add_group(&mut self, group: NamedCurve) {
        self.values.push(group)
    }

    pub fn values(&self) -> &Vec<NamedCurve> { &self.values }


    pub fn random() -> SupportedGroups {
        let mut res = SupportedGroups::new();
        res.values = vec![
            NamedCurve::X25519.into(),
            NamedCurve::Secp256r1.into(),
            NamedCurve::Secp384r1.into(),
            NamedCurve::Secp521r1.into(),
        ];
        res
    }
}