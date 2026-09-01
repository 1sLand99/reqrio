mod block;
mod derived;

use crate::boring::{EcCurve, EvpCurve, Hybrid};
use crate::buffer::Buf;
use crate::bytes::Bytes;
use crate::error::RlsResult;
use crate::{rand, NamedCurve, RlsError, Version};

pub use block::{TlsSession, KeyType};
pub(crate) use derived::DerivedKey;

pub struct TrafficSecret {
    client_traffic: [u8; 48],
    server_traffic: [u8; 48],
    size: usize,
}

impl TrafficSecret {
    pub fn client_traffic(&self) -> &[u8] {
        &self.client_traffic[..self.size]
    }

    pub fn client_traffic_mut(&mut self) -> &mut [u8] {
        &mut self.client_traffic[..self.size]
    }

    pub fn server_traffic(&self) -> &[u8] {
        &self.server_traffic[..self.size]
    }

    pub fn server_traffic_mut(&mut self) -> &mut [u8] {
        &mut self.server_traffic[..self.size]
    }
}


#[allow(non_camel_case_types)]
pub enum SecretKey {
    None,
    Evp(EvpCurve),
    Ec(EcCurve),
    PreMasterSecret(Bytes),
    Hybrid(Box<Hybrid>),
}

impl SecretKey {
    pub fn new_pre_master_secret(version: &Version) -> RlsResult<SecretKey> {
        let mut premaster_secret = vec![0; 48];
        premaster_secret[0..2].copy_from_slice(version.as_u16().to_be_bytes().as_ref());
        rand::fill(&mut premaster_secret[2..]);
        Ok(SecretKey::PreMasterSecret(Bytes::new(premaster_secret)))
    }

    pub fn new(name_cure: &NamedCurve) -> RlsResult<SecretKey> {
        match name_cure.as_u16() {
            NamedCurve::X25519 => Ok(SecretKey::Evp(EvpCurve::new_x25519()?)),
            NamedCurve::SecP256r1 => Ok(SecretKey::Ec(EcCurve::new_p256()?)),
            NamedCurve::SecP384r1 => Ok(SecretKey::Ec(EcCurve::new_p384()?)),
            NamedCurve::SecP521r1 => Ok(SecretKey::Ec(EcCurve::new_p521()?)),
            NamedCurve::X25519MLKEM768 => Ok(SecretKey::Hybrid(Box::new(Hybrid::new_x25519_768()?))),
            NamedCurve::SecP256r1MLKEM768 => Ok(SecretKey::Hybrid(Box::new(Hybrid::new_p256r1_768()?))),
            NamedCurve::ECC_SM2 => Ok(SecretKey::new_pre_master_secret(&Version::TLCP)?),
            _ => Err(format!("Unsupported name curve-{:?}", name_cure).into()),
        }
    }
    pub fn diffie_hellman(&mut self, pub_key: impl AsRef<[u8]>) -> RlsResult<Vec<u8>> {
        match self {
            SecretKey::Evp(v) => Ok(v.diffie_hellman(pub_key)?),
            SecretKey::Ec(v) => Ok(v.diffie_hellman(pub_key)?),
            SecretKey::None => Err(RlsError::Currently("PriKey mut init before".to_string())),
            SecretKey::PreMasterSecret(bytes) => Ok(bytes.as_bytes()),
            SecretKey::Hybrid(key) => Ok(key.diffie_hellman(false, pub_key.as_ref())?),
        }
    }

    pub fn pub_key(&self) -> RlsResult<Buf<'_>> {
        match self {
            SecretKey::Evp(v) => Ok(v.pub_key()?),
            SecretKey::Ec(v) => Ok(Buf::Ptr(v.pub_key()?)),
            SecretKey::None => Ok(Buf::Ref(&[])),
            SecretKey::PreMasterSecret(bytes) => Ok(Buf::Ref(bytes.as_ref())),
            SecretKey::Hybrid(key) => Ok(Buf::Ref(key.pubkey())),
        }
    }
}

