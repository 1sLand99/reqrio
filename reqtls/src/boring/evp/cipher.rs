use super::super::Padding;
use super::CipherType;
use crate::boring::bindings::*;
use crate::boring::BoringResExt;
use crate::error::RlsResult;
use crate::ffi::CPointer;
use crate::{base64, RlsError};
use std::ptr::{null, null_mut};

pub struct Cipher {
    ctx: CPointer<EVP_CIPHER_CTX>,
    evp_cipher: CipherType,
    padding: Padding,
    key: Vec<u8>,
    iv: Vec<u8>,
}

impl Cipher {
    pub(crate) fn new(cipher: CipherType) -> Cipher {
        let ctx = CPointer::new(unsafe { EVP_CIPHER_CTX_new() });
        Cipher {
            ctx,
            evp_cipher: cipher,
            padding: Padding::PKCS7Padding,
            key: vec![],
            iv: vec![],
        }
    }


    pub fn aes_128_cbc() -> Cipher { Cipher::new(CipherType::AES_128_CBC) }

    pub fn aes_192_cbc() -> Cipher {
        Cipher::new(CipherType::AES_192_CBC)
    }

    pub fn aes_256_cbc() -> Cipher {
        Cipher::new(CipherType::AES_256_CBC)
    }

    pub fn aes_128_ecb() -> Cipher {
        Cipher::new(CipherType::AES_128_ECB)
    }

    pub fn aes_192_ecb() -> Cipher {
        Cipher::new(CipherType::AES_192_ECB)
    }

    pub fn aes_256_ecb() -> Cipher {
        Cipher::new(CipherType::AES_256_ECB)
    }

    pub fn aes_128_ctr() -> Cipher {
        Cipher::new(CipherType::AES_128_CTR)
    }

    pub fn aes_192_ctr() -> Cipher {
        Cipher::new(CipherType::AES_192_CTR)
    }

    pub fn aes_256_ctr() -> Cipher {
        Cipher::new(CipherType::AES_256_CTR)
    }

    pub fn aes_128_gcm() -> Cipher {
        Cipher::new(CipherType::AES_128_GCM)
    }

    pub fn aes_192_gcm() -> Cipher {
        Cipher::new(CipherType::AES_192_GCM)
    }

    pub fn aes_256_gcm() -> Cipher {
        Cipher::new(CipherType::AES_256_GCM)
    }

    pub fn aes_128_ofb() -> Cipher {
        Cipher::new(CipherType::AES_128_OFB)
    }

    pub fn aes_192_ofb() -> Cipher {
        Cipher::new(CipherType::AES_192_OFB)
    }

    pub fn aes_256_ofb() -> Cipher {
        Cipher::new(CipherType::AES_256_OFB)
    }

    pub fn des_cbc() -> Cipher {
        Cipher::new(CipherType::DES_CBC)
    }

    pub fn des_ecb() -> Cipher {
        Cipher::new(CipherType::DES_ECB)
    }

    pub fn rc4() -> Cipher { Cipher::new(CipherType::RC4) }

    pub fn with_secret_key<T: Into<Vec<u8>>>(mut self, key: T, iv: Option<T>) -> Self {
        self.set_secret_key(key, iv);
        self
    }

    pub fn set_secret_key<T: Into<Vec<u8>>>(&mut self, key: T, iv: Option<T>) {
        self.key = key.into();
        self.iv = iv.map(|iv| iv.into()).unwrap_or(vec![]);
    }

    pub fn encrypt(&self, context: impl Into<Vec<u8>>) -> RlsResult<Vec<u8>> {
        if self.ctx.is_null() { return Err(RlsError::InitEvpCtxError); }
        let mut context = context.into();
        if !matches!(self.evp_cipher, CipherType::RC4) { self.padding.add_padding(&mut context); }
        let iv = if self.iv.is_empty() { null() } else { self.iv.as_ptr() };
        unsafe { EVP_EncryptInit_ex(self.ctx.as_mut_ptr(), self.evp_cipher.as_boring(), null_mut(), self.key.as_ptr(), iv) }.ok(RlsError::CipherCryptError)?;
        unsafe { EVP_CIPHER_CTX_set_padding(self.ctx.as_mut_ptr(), 0) };
        context.resize(context.len() + 16, 0);
        let mut block_len = 0;
        unsafe {
            EVP_EncryptUpdate(
                self.ctx.as_mut_ptr(),
                context.as_mut_ptr(),
                &mut block_len,
                context.as_ptr(),
                context.len() as i32 - 16)
        }.ok(RlsError::CipherEncryptError)?;
        let mut final_len = 0;
        unsafe {
            EVP_EncryptFinal_ex(
                self.ctx.as_mut_ptr(),
                context[block_len as usize..].as_mut_ptr(),
                &mut final_len,
            )
        }.ok(RlsError::CipherEncryptError)?;
        context.truncate((block_len + final_len) as usize);
        Ok(context)
    }

    pub fn decrypt(&self, context: impl Into<Vec<u8>>) -> RlsResult<Vec<u8>> {
        if self.ctx.is_null() { return Err(RlsError::InitEvpCtxError); }
        let iv = if self.iv.is_empty() { null() } else { self.iv.as_ptr() };
        unsafe { EVP_DecryptInit_ex(self.ctx.as_mut_ptr(), self.evp_cipher.as_boring(), null_mut(), self.key.as_ptr(), iv) }.ok(RlsError::CipherCryptError)?;
        unsafe { EVP_CIPHER_CTX_set_padding(self.ctx.as_mut_ptr(), 0) };
        let mut context = context.into();
        // 4. 执行解密
        let mut out_len = 0i32;
        let mut final_len = 0i32;
        unsafe {
            EVP_DecryptUpdate(
                self.ctx.as_mut_ptr(),
                context.as_mut_ptr(),
                &mut out_len,
                context.as_ptr(),
                context.len() as i32,
            )
        }.ok(RlsError::CipherDecryptError)?;
        unsafe {
            EVP_DecryptFinal_ex(
                self.ctx.as_mut_ptr(),
                context.as_mut_ptr().add(out_len as usize),
                &mut final_len,
            )
        }.ok(RlsError::CipherDecryptError)?;
        context.truncate((out_len + final_len) as usize);
        if !matches!(self.evp_cipher, CipherType::RC4) { self.padding.remove_padding(&mut context); }
        Ok(context)
    }
}

pub fn en_b64<T: Into<Vec<u8>>>(typ: CipherType, key: T, iv: Option<T>, data: impl Into<Vec<u8>>) -> RlsResult<String> {
    let cipher = Cipher::new(typ).with_secret_key(key, iv);
    let en_bs = cipher.encrypt(data)?;
    Ok(base64::b64encode(en_bs)?)
}

pub fn de_b64<T: Into<Vec<u8>>>(typ: CipherType, key: T, iv: Option<T>, data: impl AsRef<[u8]>) -> RlsResult<Vec<u8>> {
    let de_b64 = base64::b64decode(data)?;
    let cipher = Cipher::new(typ).with_secret_key(key, iv);
    cipher.decrypt(de_b64)
}

pub fn en_hex<T: Into<Vec<u8>>>(typ: CipherType, key: T, iv: Option<T>, data: impl Into<Vec<u8>>) -> RlsResult<String> {
    let cipher = Cipher::new(typ).with_secret_key(key, iv);
    let en_bs = cipher.encrypt(data)?;
    Ok(hex::encode(en_bs))
}

pub fn de_hex<T: Into<Vec<u8>>>(typ: CipherType, key: T, iv: Option<T>, data: impl AsRef<[u8]>) -> RlsResult<Vec<u8>> {
    let de_hex = hex::decode(data)?;
    let cipher = Cipher::new(typ).with_secret_key(key, iv);
    cipher.decrypt(de_hex)
}