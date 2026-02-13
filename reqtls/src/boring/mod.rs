#[cfg(feature = "tls")]
mod ec_curve;
#[allow(dead_code)]
pub(crate) mod bindings;
pub mod hash;
#[cfg(feature = "tls")]
mod signature;

pub use rsa::{RsaCipher, RsaKey, certificate};
pub(crate) mod rsa;

mod evp;
mod padding;
pub mod base64;

pub use padding::Padding;

pub use evp::{Cipher, CipherType, cipher};
#[cfg(feature = "tls")]
pub use evp::{CipherCrypto, EvpCurve, AeadCrypto};

#[cfg(feature = "tls")]
pub use ec_curve::*;
pub use hash::*;

#[cfg(feature = "tls")]
pub use signature::{AlgorithmSigner, SignatureAlgorithm};
use std::ffi::c_int;

use crate::error::RlsResult;
#[cfg(feature = "tls")]
use crate::extend::Aead;
#[cfg(feature = "tls")]
use crate::message::Payload;
use crate::RlsError;

trait BoringResExt {
    fn ok(self, error: RlsError) -> RlsResult<()>;
}

impl BoringResExt for c_int {
    fn ok(self, error: RlsError) -> RlsResult<()> {
        if self != 1 { return Err(error); }
        Ok(())
    }
}


#[cfg(feature = "tls")]
pub(crate) struct CryptParam<'a, 'b: 'a> {
    pub(crate) aead: &'a Aead,
    pub(crate) nonce: &'a [u8],
    pub(crate) iv: &'a [u8],
    pub(crate) aad: &'a [u8; 13],
    pub(crate) payload: &'a mut Payload<'b>,
}

#[cfg(feature = "tls")]
pub enum Crypto {
    None,
    Aead(Box<AeadCrypto>),
    Cipher(CipherCrypto),
}

#[cfg(feature = "tls")]
impl Crypto {
    pub fn from_aead(key: &[u8], aead: &Aead) -> RlsResult<Crypto> {
        match aead {
            Aead::AES_128_GCM | Aead::AES_256_GCM | Aead::ChaCha20_POLY1305 => Ok(Crypto::Aead(Box::new(AeadCrypto::new(aead, key)?))),
            Aead::AES_128_CBC_SHA | Aead::AES_256_CBC_SHA => Ok(Crypto::Cipher(CipherCrypto::new(aead, key.to_vec())?)),
            _ => Err("unsupported cryptor".into()),
        }
    }

    pub fn encrypt(&self, param: CryptParam) -> RlsResult<usize> {
        match self {
            Crypto::Aead(cryptor) => cryptor.encrypt(param),
            Crypto::Cipher(cipher) => cipher.encrypt(param),
            _ => Err("Cryptor not implemented".into()),
        }
    }

    pub fn decrypt(&self, param: CryptParam) -> RlsResult<usize> {
        match self {
            Crypto::Aead(crypto) => crypto.decrypt(param),
            Crypto::Cipher(cipher) => cipher.decrypt(param),
            _ => Err("Cryptor not implemented".into()),
        }
    }
}