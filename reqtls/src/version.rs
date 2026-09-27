use std::cmp::Ordering;
use std::fmt::{Debug, Formatter};
use crate::REVERSED;

#[repr(C)]
#[derive(Copy, Clone, PartialEq)]
pub struct Version(u16);

impl Version {
    pub const TLS_1_0: Version = Version(0x301);
    pub const TLS_1_1: Version = Version(0x302);
    pub const TLS_1_2: Version = Version(0x303);
    pub const TLS_1_3: Version = Version(0x304);
    pub const TLCP: Version = Version(0x101);
    pub const ALL: [Version; 5] = [
        Version::TLS_1_0,
        Version::TLS_1_1,
        Version::TLS_1_2,
        Version::TLS_1_3,
        Version::TLCP
    ];
}

impl Version {
    pub const fn new(v: u16) -> Version {
        Version(v)
    }

    pub const fn into_inner(self) -> u16 { self.0 }

    pub const fn inner(&self) -> u16 {
        self.0
    }

    pub const fn spec(&self) -> &str {
        match self.0 {
            0x301 => "TLS_1_0",
            0x302 => "TLS_1_1",
            0x303 => "TLS_1_2",
            0x304 => "TLS_1_3",
            0x101 => "TLCP",
            _ => "Reversed"
        }
    }

    pub fn is_reversed(&self) -> bool {
        REVERSED.contains(&self.0)
    }
}

impl Debug for Version {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}(0x{:04x})", self.spec(), self.0)
    }
}

impl From<u16> for Version {
    fn from(v: u16) -> Version {
        Version(v)
    }
}

impl PartialEq<u16> for Version {
    fn eq(&self, other: &u16) -> bool {
        self.0 == *other
    }
}

impl PartialOrd<u16> for Version {
    fn partial_cmp(&self, other: &u16) -> Option<Ordering> {
        self.0.partial_cmp(other)
    }
}