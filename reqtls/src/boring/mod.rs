mod aead;
mod cipher;
mod ec_curve;
mod evp_curve;
mod bindings;
pub mod hash;
mod signature;

pub use rsa::{Certificate, RsaCipher, RsaKey};
mod rsa;
mod ffi;

pub use cipher::{base64, Cipher, Padding};
pub use ec_curve::*;
pub use evp_curve::*;
pub use ffi::Buf;
use ffi::CPointerMut;
pub use hash::*;
pub use signature::{AlgorithmSigner, SignatureAlgorithm};
use std::ffi::c_int;

use crate::error::RlsResult;
use crate::extend::Aead;
use crate::message::Payload;
use crate::RlsError;
use aead::AeadCryptor;
use cipher::CipherCryptor;

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

pub enum Cryptor {
    None,
    Aead(Box<AeadCryptor>),
    Cipher(CipherCryptor),
}

impl Cryptor {
    pub fn from_aead(key: &[u8], aead: &Aead) -> RlsResult<Cryptor> {
        match aead {
            Aead::AES_128_GCM | Aead::AES_256_GCM | Aead::ChaCha20_POLY1305 => Ok(Cryptor::Aead(Box::new(AeadCryptor::new(aead, key)?))),
            Aead::AES_128_CBC_SHA | Aead::AES_256_CBC_SHA => Ok(Cryptor::Cipher(CipherCryptor::new(aead, key.to_vec())?)),
            _ => Err("unsupported cryptor".into()),
        }
    }

    pub fn encrypt(&self, param: CryptParam) -> RlsResult<usize> {
        match self {
            Cryptor::Aead(cryptor) => cryptor.encrypt(param),
            Cryptor::Cipher(cipher) => cipher.encrypt(param),
            _ => Err("Cryptor not implemented".into()),
        }
    }

    pub fn decrypt(&self, param: CryptParam) -> RlsResult<usize> {
        match self {
            Cryptor::Aead(cryptor) => cryptor.decrypt(param),
            Cryptor::Cipher(cipher) => cipher.decrypt(param),
            _ => Err("Cryptor not implemented".into()),
        }
    }
}