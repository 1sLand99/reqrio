use std::fmt::Debug;

#[derive(Copy, Clone)]
pub struct PskMode(u8);

impl PskMode {
    pub const PSK_DHE_KE: u8 = 0x1;
    pub fn new(value: u8) -> PskMode { PskMode(value) }

    pub fn into_inner(self) -> u8 { self.0 }

    fn spec(&self) -> &str {
        match self.0 {
            PskMode::PSK_DHE_KE => "PSK_DHE_KE",
            _ => "Reserved"
        }
    }
}

impl Debug for PskMode {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}(0x{:02x})", self.spec(), self.0)
    }
}

impl From<u8> for PskMode {
    fn from(value: u8) -> PskMode {
        PskMode(value)
    }
}