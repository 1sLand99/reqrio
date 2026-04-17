mod block;
mod derived;

pub use block::Key;
pub use derived::DerivedKey;
use crate::boring::{EcCurve, EvpCurve};
use crate::bytes::Bytes;
use crate::error::RlsResult;
use crate::{rand, NamedCurve, RlsError, X25519MlKem768};
use crate::buffer::Buf;

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
    Hybrid(X25519MlKem768),
}

impl SecretKey {
    pub fn new_pre_master_secret() -> RlsResult<SecretKey> {
        let mut master_secret = vec![3, 3];
        master_secret.extend(rand::random::<[u8; 46]>());
        Ok(SecretKey::PreMasterSecret(Bytes::new(master_secret)))
    }

    pub fn new(name_cure: impl Into<NamedCurve>) -> RlsResult<SecretKey> {
        match name_cure.into().as_u16() {
            NamedCurve::X25519 => Ok(SecretKey::Evp(EvpCurve::new_x25519()?)),
            NamedCurve::Secp256r1 => Ok(SecretKey::Ec(EcCurve::new_p256()?)),
            NamedCurve::Secp384r1 => Ok(SecretKey::Ec(EcCurve::new_p384()?)),
            NamedCurve::Secp521r1 => Ok(SecretKey::Ec(EcCurve::new_p521()?)),
            NamedCurve::X25519MLKEM768 => Ok(SecretKey::Hybrid(X25519MlKem768::new_client()?)),
            _ => Err("Unsupported name curve".into()),
        }
    }
    pub fn diffie_hellman(&mut self, pub_key: impl AsRef<[u8]>) -> RlsResult<Vec<u8>> {
        match self {
            SecretKey::Evp(v) => Ok(v.diffie_hellman(pub_key)?),
            SecretKey::Ec(v) => v.diffie_hellman(pub_key),
            SecretKey::None => Err(RlsError::Currently("PriKey mut init before".to_string())),
            SecretKey::PreMasterSecret(bytes) => Ok(bytes.as_bytes()),
            SecretKey::Hybrid(key) => Ok(key.diffie_hellman(false, pub_key.as_ref())?)
        }
    }

    pub fn pub_key(&self) -> RlsResult<Buf<'_>> {
        match self {
            SecretKey::Evp(v) => Ok(v.pub_key()?),
            SecretKey::Ec(v) => Ok(Buf::Ptr(v.pub_key()?)),
            SecretKey::None => Ok(Buf::Ref(&[])),
            SecretKey::PreMasterSecret(bytes) => Ok(Buf::Ref(bytes.as_ref())),
            SecretKey::Hybrid(key) => Ok(Buf::Ref(key.pub_key())),
        }
    }
}

