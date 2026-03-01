use std::fmt::{Debug, Formatter};
use crate::error::RlsResult;
use crate::WriteExt;

pub struct GroupType(u16);

impl GroupType {
    pub const X25519: GroupType = GroupType(0x1d);
    pub const X25519MLKEM768: GroupType = GroupType(0x11ec);
    #[allow(non_upper_case_globals)]
    pub const Secp256r1: GroupType = GroupType(0x0017);
    #[allow(non_upper_case_globals)]
    pub const Secp384r1: GroupType = GroupType(0x0018);
    #[allow(non_upper_case_globals)]
    pub const Secp521r1: GroupType = GroupType(0x0019);
    pub fn new(v: u16) -> GroupType {
        GroupType(v)
    }

    pub fn into_inner(self) -> u16 { self.0 }
    
    pub fn as_u16(&self) -> u16 {
        self.0
    }

    pub fn is_reserved(&self) -> bool {
        !matches!(self.0, 0x1d | 0x11ec | 0x0017 | 0x0018 | 0x0019)
    }
}

impl Debug for GroupType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            0x1d => write!(f, "X25519(0x1d)"),
            0x11ec => write!(f, "X25519MLKEM768(0x11ec)"),
            0x0017 => write!(f, "Secp256r1(0x0017)"),
            0x0018 => write!(f, "Secp384r1(0x0018)"),
            0x0019 => write!(f, "Secp521r1(0x0019)"),
            _ => write!(f, "Reserved({})", self.0),
        }
    }
}


#[derive(Debug)]
pub struct SupportedGroups {
    len: u16,
    values: Vec<GroupType>,
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
            res.values.push(GroupType::new(v));
        }
        Ok(res)
    }

    pub fn len(&self) -> usize {
        self.values.len() * 2 + 2
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) {
        writer.write_u16(self.len() as u16 - 2);
        for value in self.values {
            writer.write_u16(value.into_inner());
        }
    }
    
    pub fn clear(&mut self) {
        self.values.clear();
    }

    pub fn set_values(&mut self, values: Vec<GroupType>) {
        self.values = values;
    }
    pub fn add_group(&mut self, group: GroupType) {
        self.values.push(group)
    }

    pub fn values(&self) -> &Vec<GroupType> { &self.values }


    pub fn random() -> SupportedGroups {
        let mut res = SupportedGroups::new();
        res.values = vec![
            GroupType::X25519,
            GroupType::Secp256r1,
            GroupType::Secp384r1,
            GroupType::Secp521r1,
        ];
        res
    }
}