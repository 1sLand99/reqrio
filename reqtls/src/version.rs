use std::fmt::{Debug, Formatter};

#[derive(PartialEq)]
pub struct Version(u16);

impl Version {
    pub const TLS_1_0: Version = Version(0x301);
    pub const TLS_1_1: Version = Version(0x302);
    pub const TLS_1_2: Version = Version(0x303);
    pub const TLS_1_3: Version = Version(0x304);
}

impl Version {
    pub fn new(v: u16) -> Version {
        Version(v)
    }

    pub(crate) fn as_bytes(&self) -> [u8; 2] {
        self.0.to_be_bytes()
    }

    pub(crate) fn as_u16(&self) -> u16 {
        self.0
    }

    pub(crate) fn as_ja4_str(&self) -> &'static str {
        match self.0 {
            0x301 => "10",
            0x302 => "11",
            0x303 => "12",
            0x304 => "13",
            _ => ""
        }
    }

    pub(crate) fn is_reverse(&self) -> bool {
        !matches!(self.0, 0x301..=0x304)
    }
}

impl Debug for Version {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            0x301 => write!(f, "TLS_1_0(0x{:x})", self.0),
            0x302 => write!(f, "TLS_1_1(0x{:x})", self.0),
            0x303 => write!(f, "TLS_1_2(0x{:x})", self.0),
            0x304 => write!(f, "TLS_1_3(0x{:x})", self.0),
            _ => write!(f, "Reserved({})", self.0)
        }
    }
}