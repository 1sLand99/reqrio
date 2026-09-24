#[cfg(debug_assertions)]
use std::fmt::Debug;
use std::fmt::{Display, Formatter};

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct PskMode(u8);

impl PskMode {
    pub const PSK_DHE_KE: PskMode = PskMode::new(0x1);
    pub const fn new(value: u8) -> PskMode { PskMode(value) }

    pub fn into_inner(self) -> u8 { self.0 }

    fn spec(&self) -> &str {
        match *self {
            PskMode::PSK_DHE_KE => "PSK_DHE_KE",
            _ => "Reserved"
        }
    }
}

#[cfg(debug_assertions)]
impl Debug for PskMode {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{}(0x{:02x})", self.spec(), self.0)
    }
}

impl Display for PskMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}(0x{:02x})", self.spec(), self.0)
    }
}

impl From<u8> for PskMode {
    fn from(value: u8) -> PskMode {
        PskMode(value)
    }
}