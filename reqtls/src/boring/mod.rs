mod ec_curve;
mod bindings;
pub mod hash;
mod signature;

pub use rsa::{Certificate, RsaCipher, RsaKey};
mod rsa;
mod ffi;
mod evp;
mod padding;
pub mod base64;

pub use padding::Padding;
pub use evp::{EvpCurve, Cipher, CipherCrypto, AeadCrypto};
pub use ec_curve::*;
pub use ffi::Buf;
use ffi::CPointer;
pub use hash::*;
pub use signature::{AlgorithmSigner, SignatureAlgorithm};
use std::ffi::c_int;

use crate::error::RlsResult;
use crate::extend::Aead;
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


pub(crate) struct CryptParam<'a, 'b: 'a> {
    pub(crate) aead: &'a Aead,
    pub(crate) nonce: &'a [u8],
    pub(crate) iv: &'a [u8],
    pub(crate) aad: &'a [u8; 13],
    pub(crate) payload: &'a mut Payload<'b>,
}

pub enum Crypto {
    None,
    Aead(Box<AeadCrypto>),
    Cipher(CipherCrypto),
}

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