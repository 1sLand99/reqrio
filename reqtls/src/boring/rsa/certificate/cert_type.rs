use std::fmt::{Debug, Formatter};

#[derive(PartialEq)]
pub struct CertType(u8);
impl CertType {
    pub const RSA: CertType = CertType(1);
    pub const ECDSA: CertType = CertType(64);
    //未知
    pub const ED25519: CertType = CertType(0);


    pub fn spec(&self) -> &str {
        match *self {
            CertType::RSA => "RSA",
            CertType::ECDSA => "ECDSA",
            _ => "Reserved"
        }
    }
    pub fn new(v: u8) -> CertType {
        CertType(v)
    }
}

impl Debug for CertType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}(0x{})", self.spec(), self.0)
    }
}