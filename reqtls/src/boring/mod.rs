mod aead;
mod cipher;

use crate::error::RlsResult;
use crate::extend::Aead;
use crate::message::Payload;
use aead::AeadCryptor;
use cipher::CipherCryptor;

pub(crate) struct CryptParam<'a, 'b: 'a> {
    pub(crate) aead: &'a Aead,
    pub(crate) nonce: &'a [u8],
    pub(crate) iv: &'a [u8],
    pub(crate) aad: &'a [u8; 13],
    pub(crate) payload: &'a mut Payload<'b>,
}

pub enum Cryptor {
    None,
    AeadCryptor(AeadCryptor),
    CipherCryptor(CipherCryptor),
}

impl Cryptor {
    pub fn from_aead(key: &[u8], aead: &Aead) -> RlsResult<Cryptor> {
        match aead {
            Aead::AES_128_GCM | Aead::AES_256_GCM | Aead::ChaCha20_POLY1305 => Ok(Cryptor::AeadCryptor(AeadCryptor::new(aead, key)?)),
            Aead::AES_128_CBC_SHA | Aead::AES_256_CBC_SHA => Ok(Cryptor::CipherCryptor(CipherCryptor::new(aead, key.to_vec())?)),
            _=>return Err("unsupported cryptor".into()),
        }
    }

    pub fn encrypt(&self, param: CryptParam) -> RlsResult<usize> {
        match self {
            Cryptor::AeadCryptor(cryptor) => cryptor.encrypt(param),
            Cryptor::CipherCryptor(cipher) => cipher.encrypt(param),
            _ => Err("Cryptor not implemented".into()),
        }
    }

    pub fn decrypt(&self, param: CryptParam) -> RlsResult<usize> {
        match self {
            Cryptor::AeadCryptor(cryptor) => cryptor.decrypt(param),
            Cryptor::CipherCryptor(cipher) => cipher.decrypt(param),
            _ => Err("Cryptor not implemented".into()),
        }
    }
}