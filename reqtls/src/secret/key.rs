use super::super::message::key_exchange::NamedCurve;
use crate::boring::{EcCurve, EvpCurve};
use crate::error::RlsResult;

#[allow(non_camel_case_types)]
pub enum PriKey {
    Evp(EvpCurve),
    Ec(EcCurve),
}

impl PriKey {
    pub fn new(name_cure: &NamedCurve) -> RlsResult<PriKey> {
        match name_cure {
            NamedCurve::x25519 => Ok(PriKey::Evp(EvpCurve::new_x25519()?)),
            NamedCurve::Secp256r1 => Ok(PriKey::Ec(EcCurve::new_p256()?)),
            NamedCurve::Secp384r1 => Ok(PriKey::Ec(EcCurve::new_p384()?)),
            NamedCurve::Secp521r1 => Ok(PriKey::Ec(EcCurve::new_p521()?)),
        }
    }
    pub fn diffie_hellman(self, pub_key: impl AsRef<[u8]>) -> RlsResult<Vec<u8>> {
        match self {
            PriKey::Evp(v) => v.diffie_hellman(pub_key),
            PriKey::Ec(v) => v.diffie_hellman(pub_key),
        }
    }

    pub fn pub_key(&mut self) -> &[u8] {
        match self {
            PriKey::Evp(v) => v.pub_key(),
            PriKey::Ec(v) => v.pub_key(),
        }
    }
}

