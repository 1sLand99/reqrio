mod ec_curve;
pub(crate) mod bindings;
pub mod hash;
mod signature;

pub(crate) mod rsa;

mod evp;
mod padding;
pub mod base64;
mod ml_kem;

use crate::boring::bindings::EVP_AEAD_DEFAULT_TAG_LENGTH;
use crate::buffer::{CipherDecodeBuffer, CipherEncodeBuffer};
use crate::error::RlsResult;
use crate::{CipherSuite, RlsError};
pub use ec_curve::*;
pub use evp::{cipher, Cipher, CipherType, EvpError, PKey, PKeyCtx, PKeyError};
pub use evp::{AeadCtx, CipherCrypto, EvpCurve};
pub use hash::*;
pub use ml_kem::{Hybrid, MLKEMError};
pub use padding::Padding;
pub use rsa::{certificate, RsaCipher, RsaKey, RsaPadding};
pub use signature::{AlgorithmSigner, SignatureAlgorithm};
use std::ffi::c_int;

pub trait BoringResExt {
    fn ok<E>(self, error: E) -> Result<(), E>;
}

impl BoringResExt for c_int {
    fn ok<E>(self, error: E) -> Result<(), E> {
        if self != 1 { return Err(error); }
        Ok(())
    }
}


pub(crate) struct CryptEncodeParam<'a, 'b: 'a> {
    pub(crate) nonce: &'a [u8],
    pub(crate) iv: &'a [u8],
    pub(crate) aad: &'a [u8],
    pub(crate) seq: &'a u64,
    pub(crate) buffer: &'a mut CipherEncodeBuffer<'b>,
}

pub(crate) struct CryptDecodeParam<'a, 'b: 'a> {
    pub(crate) nonce: &'a [u8],
    pub(crate) iv: &'a [u8],
    pub(crate) aad: &'a [u8],
    pub(crate) seq: &'a u64,
    pub(crate) buffer: &'a mut CipherDecodeBuffer<'b>,
}

pub enum Crypto {
    None,
    Aead(AeadCtx),
    Cipher(CipherCrypto),
}

impl Crypto {
    pub fn from_aead(key: &[u8], mac_key: &[u8], suite: &'static CipherSuite) -> RlsResult<Crypto> {
        match suite.cipher() {
            CipherType::AES_128_GCM |
            CipherType::AES_192_GCM |
            CipherType::AES_256_GCM |
            CipherType::CHACHA20_POLY1305 |
            CipherType::SM4_GCM => {
                let aead = suite.aead().ok_or(RlsError::AeadNone)?;
                Ok(Crypto::Aead(AeadCtx::new(aead, key, EVP_AEAD_DEFAULT_TAG_LENGTH)?))
            }
            CipherType::AES_128_CBC |
            CipherType::AES_256_CBC |
            CipherType::SM4_CBC => {
                Ok(Crypto::Cipher(CipherCrypto::new(suite.cipher(), key.to_vec(), mac_key.to_vec(), suite.mac_hash())?))
            }
            _ => Err("unsupported cipher type")?,
        }
    }

    pub fn encrypt(&self, param: CryptEncodeParam) -> RlsResult<()> {
        match self {
            Crypto::Aead(cryptor) => cryptor.seal(param),
            Crypto::Cipher(cipher) => cipher.encrypt(param),
            _ => Err("Cryptor not implemented".into()),
        }
    }

    pub fn decrypt(&self, param: CryptDecodeParam) -> RlsResult<usize> {
        match self {
            Crypto::Aead(crypto) => crypto.open(param),
            Crypto::Cipher(cipher) => cipher.decrypt(param),
            _ => Err("Cryptor not implemented".into()),
        }
    }
}