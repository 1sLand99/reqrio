use crate::error::RlsResult;
use crate::{BufferError, NamedCurve, ReadExt, Reader, WriteExt};
use std::fmt::Debug;


#[derive(Debug)]
pub struct SupportedGroups {
    values: Vec<NamedCurve>,
}

impl SupportedGroups {
    pub fn new() -> SupportedGroups {
        SupportedGroups {
            values: vec![],
        }
    }
    pub fn from_reader(mut reader: Reader<'_>) -> RlsResult<SupportedGroups> {
        let len = reader.read_u16()?;
        let mut values=Vec::with_capacity(reader.unread_len());
        for _ in (0..len).step_by(2) {
            values.push(NamedCurve::new(reader.read_u16()?))
        }
        Ok(SupportedGroups { values })
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