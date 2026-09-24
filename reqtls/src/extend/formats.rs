#[cfg(debug_assertions)]
use std::fmt::{Debug, Formatter};

#[repr(C)]
#[derive(Clone, PartialEq, Copy)]
pub struct EcPointFormat(u8);

impl EcPointFormat {
    pub const UNCOMPRESSED: EcPointFormat = EcPointFormat(0x0);
    pub const ANSI_X962_PRIME: EcPointFormat = EcPointFormat(0x1);
    pub const ANSI_X962_CHAR2: EcPointFormat = EcPointFormat(0x2);
    pub const ALL: [EcPointFormat; 3] = [EcPointFormat::UNCOMPRESSED, EcPointFormat::ANSI_X962_PRIME, EcPointFormat::ANSI_X962_CHAR2];

    pub const fn spec(&self) -> &str {
        match *self {
            EcPointFormat::UNCOMPRESSED => "UNCOMPRESSED",
            EcPointFormat::ANSI_X962_PRIME => "ANSI_X962_PRIME",
            EcPointFormat::ANSI_X962_CHAR2 => "ANSI_X962_CHAR2",
            _ => "Reserved"
        }
    }
    pub const fn into_inner(self) -> u8 {
        self.0
    }

    pub const fn new(v: u8) -> EcPointFormat {
        EcPointFormat(v)
    }
}

#[cfg(debug_assertions)]
impl Debug for EcPointFormat {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}(0x{:02x})", self.spec(), self.0)
    }
}

impl From<u8> for EcPointFormat {
    fn from(v: u8) -> EcPointFormat {
        EcPointFormat::new(v)
    }
}