use super::super::message::key_exchange::NamedCurve;
use crate::boring::{EcCurve, EvpCurve};
use crate::error::RlsResult;
use crate::RlsError;

#[allow(non_camel_case_types)]
pub enum SharedKey {
    None,
    Evp(EvpCurve),
    Ec(EcCurve),
}

impl SharedKey {
    pub fn new(name_cure: &NamedCurve) -> RlsResult<SharedKey> {
        match name_cure {
            NamedCurve::x25519 => Ok(SharedKey::Evp(EvpCurve::new_x25519()?)),
            NamedCurve::Secp256r1 => Ok(SharedKey::Ec(EcCurve::new_p256()?)),
            NamedCurve::Secp384r1 => Ok(SharedKey::Ec(EcCurve::new_p384()?)),
            NamedCurve::Secp521r1 => Ok(SharedKey::Ec(EcCurve::new_p521()?)),
        }
    }
    pub fn diffie_hellman(&mut self, pub_key: impl AsRef<[u8]>) -> RlsResult<Vec<u8>> {
        match self {
            SharedKey::Evp(v) => v.diffie_hellman(pub_key),
            SharedKey::Ec(v) => v.diffie_hellman(pub_key),
            SharedKey::None => Err(RlsError::Currently("PriKey mut init before".to_string()))
        }
    }

    pub fn pub_key(&mut self) -> &[u8] {
        match self {
            SharedKey::Evp(v) => v.pub_key(),
            SharedKey::Ec(v) => v.pub_key(),
            SharedKey::None => &[]
        }
    }
}

