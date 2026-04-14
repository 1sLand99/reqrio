#[derive(Debug, Clone, Copy)]
#[allow(non_camel_case_types)]
pub enum KDF {
    HKDF_SHA256 = 0x1,
}

impl KDF {
    pub(crate) fn from_u16(v: u16) -> Option<KDF> {
        match v {
            0x01 => Some(KDF::HKDF_SHA256),
            _ => None
        }
    }
}