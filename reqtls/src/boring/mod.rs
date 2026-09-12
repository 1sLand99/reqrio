mod ec_curve;
pub(crate) mod bindings;
pub mod hash;
mod signature;

pub(crate) mod rsa;

mod evp;
mod padding;
pub mod base64;
mod ml_kem;

use crate::buffer::{CipherEncodeBuffer, TlsDecodeBuffer};
use crate::error::RlsResult;
use crate::{Aead, CipherSuite};
pub use ec_curve::*;
pub use evp::{cipher, Cipher, CipherType, EvpError};
pub use evp::{AeadCtx, X25519, AeadDir};
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
    pub(crate) aad: &'a [u8],
    pub(crate) buffer: &'a mut CipherEncodeBuffer<'b>,
}

pub(crate) struct CryptDecodeParam<'a, 'b: 'a> {
    pub(crate) nonce: &'a [u8],
    pub(crate) aad: &'a [u8],
    pub(crate) buffer: &'a mut TlsDecodeBuffer<'b>,
}

pub enum Crypto {
    None,
    Aead(AeadCtx),
}

impl Crypto {
    pub fn from_aead(key: &[u8], mac_key: &[u8], suite: &'static CipherSuite, dir: AeadDir) -> RlsResult<Crypto> {
        match *suite.aead() {
            Aead::AES_128_GCM |
            Aead::AES_256_GCM |
            Aead::ChaCha20_POLY1305 |
            Aead::SM4_GCM => Ok(Crypto::Aead(AeadCtx::new_with_key(*suite.aead(), key, dir)?)),
            Aead::AES_128_CBC_SHA |
            Aead::AES_128_CBC_SHA256 |
            Aead::AES_256_CBC_SHA |
            Aead::AES_256_CBC_SHA256 |
            Aead::AES_256_CBC_SHA384 |
            Aead::SM4_CBC_SM3
            => {
                let mut real_key = Vec::with_capacity(mac_key.len() + key.len());
                real_key.extend(mac_key);
                real_key.extend(key);
                Ok(Crypto::Aead(AeadCtx::new_with_key(*suite.aead(), &real_key, dir)?))
            }
            _ => Err("unsupported cipher type")?,
        }
    }

    pub fn encrypt(&self, param: CryptEncodeParam) -> RlsResult<()> {
        match self {
            Crypto::Aead(cryptor) => cryptor.seal(param),
            _ => Err("Cryptor not implemented".into()),
        }
    }

    pub fn decrypt(&self, param: CryptDecodeParam) -> RlsResult<usize> {
        match self {
            Crypto::Aead(crypto) => crypto.open(param),
            _ => Err("Cryptor not implemented".into()),
        }
    }
}