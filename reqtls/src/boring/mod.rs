mod ec_curve;
pub(crate) mod bindings;
pub mod hash;
mod signature;

pub use rsa::{certificate, RsaCipher, RsaKey, RsaPadding};
pub(crate) mod rsa;

mod evp;
mod padding;
pub mod base64;

pub use padding::Padding;

pub use evp::{cipher, Cipher, CipherType};
pub use evp::{AeadCrypto, CipherCrypto, EvpCurve};

pub use ec_curve::*;
pub use hash::*;

use crate::buffer::{RecordDecodeBuffer, RecordEncodeBuffer};
use crate::error::RlsResult;
use crate::extend::Aead;
pub use signature::{AlgorithmSigner, SignatureAlgorithm};
use std::ffi::c_int;

trait BoringResExt {
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
    pub(crate) buffer: &'a mut RecordEncodeBuffer<'b>,
}

pub(crate) struct CryptDecodeParam<'a, 'b: 'a> {
    pub(crate) nonce: &'a [u8],
    pub(crate) iv: &'a [u8],
    pub(crate) aad: &'a [u8],
    pub(crate) seq: &'a u64,
    pub(crate) buffer: &'a mut RecordDecodeBuffer<'b>,
}

pub enum Crypto {
    None,
    Aead(Box<AeadCrypto>),
    Cipher(CipherCrypto),
}

impl Crypto {
    pub fn from_aead(key: &[u8], mac_key: &[u8], aead: &Aead, hash: HashType) -> RlsResult<Crypto> {
        match aead {
            Aead::AES_128_GCM | Aead::AES_256_GCM | Aead::ChaCha20_POLY1305 => Ok(Crypto::Aead(Box::new(AeadCrypto::new(aead, key)?))),
            Aead::AES_128_CBC_SHA | Aead::AES_256_CBC_SHA => Ok(Crypto::Cipher(CipherCrypto::new(aead, key.to_vec(), mac_key.to_vec(), hash)?)),
            _ => Err("unsupported cryptor".into()),
        }
    }

    pub fn encrypt(&self, param: CryptEncodeParam) -> RlsResult<()> {
        match self {
            Crypto::Aead(cryptor) => cryptor.encrypt(param),
            Crypto::Cipher(cipher) => cipher.encrypt(param),
            _ => Err("Cryptor not implemented".into()),
        }
    }

    pub fn decrypt(&self, param: CryptDecodeParam) -> RlsResult<usize> {
        match self {
            Crypto::Aead(crypto) => crypto.decrypt(param),
            Crypto::Cipher(cipher) => cipher.decrypt(param),
            _ => Err("Cryptor not implemented".into()),
        }
    }
}