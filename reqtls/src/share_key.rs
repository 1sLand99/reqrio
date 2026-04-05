use super::message::key_exchange::NamedCurve;
use crate::boring::{EcCurve, EvpCurve};
use crate::bytes::Bytes;
use crate::error::RlsResult;
use crate::{rand, RlsError};
use crate::buffer::Buf;

#[allow(non_camel_case_types)]
pub enum SharedKey {
    None,
    Evp(EvpCurve),
    Ec(EcCurve),
    PreMasterSecret(Bytes),
}

impl SharedKey {
    pub fn new_pre_master_secret() -> RlsResult<SharedKey> {
        let mut master_secret = vec![3, 3];
        master_secret.extend(rand::random::<[u8; 46]>());
        Ok(SharedKey::PreMasterSecret(Bytes::new(master_secret)))
    }

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
            SharedKey::None => Err(RlsError::Currently("PriKey mut init before".to_string())),
            SharedKey::PreMasterSecret(bytes) => Ok(bytes.as_bytes()),
        }
    }

    pub fn pub_key(&self) -> RlsResult<Buf<'_>> {
        match self {
            SharedKey::Evp(v) => v.pub_key(),
            SharedKey::Ec(v) => Ok(Buf::Ptr(v.pub_key()?)),
            SharedKey::None => Ok(Buf::Ref(&[])),
            SharedKey::PreMasterSecret(bytes) => Ok(Buf::Ref(bytes.as_ref())),
        }
    }
}

