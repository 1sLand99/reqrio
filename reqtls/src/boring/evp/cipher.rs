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

    pub fn encrypt(&self, context: impl AsRef<[u8]>) -> RlsResult<Vec<u8>> {
        if self.ctx.is_null() { return Err(RlsError::InitEvpCtxError); }
        let mut out = vec![0; context.as_ref().len() + 16];
        let padding = if !matches!(self.evp_cipher, CipherType::RC4) { self.padding.add_padding(context.as_ref()) } else { vec![] };
        let iv = if self.iv.is_empty() { null() } else { self.iv.as_ptr() };
        self.init_encrypt(self.key.as_ptr(), iv)?;
        let ptr = context.as_ref().as_ptr();
        let out_ptr = out.as_mut_ptr();
        let block_len = self.encrypt_update(ptr, context.as_ref().len(), out_ptr)?;
        let out_ptr = unsafe { out_ptr.add(block_len) };
        let padding_len = self.encrypt_update(padding.as_ptr(), padding.len(), out_ptr)?;
        let out_ptr = unsafe { out_ptr.add(padding_len) };
        let final_len = self.encrypt_finalize(out_ptr)?;
        out.truncate(block_len + padding_len + final_len);
        Ok(out)
    }

    pub fn decrypt(&self, context: impl Into<Vec<u8>>) -> RlsResult<Vec<u8>> {
        if self.ctx.is_null() { return Err(RlsError::InitEvpCtxError); }
        let iv = if self.iv.is_empty() { null() } else { self.iv.as_ptr() };
        self.init_decrypt(self.key.as_ptr(), iv)?;
        let mut context = context.into();
        let ptr = context.as_ptr();
        let out = context.as_mut_ptr();
        let out_len = self.decrypt_update(ptr, context.len(), out)?;
        let out = unsafe { out.add(out_len) };
        let final_len = self.decrypt_finalize(out)?;
        context.truncate(out_len + final_len);
        if !matches!(self.evp_cipher, CipherType::RC4) { self.padding.remove_padding(&mut context); }
        Ok(context)
    }

    pub(crate) fn init_encrypt(&self, key: *const u8, iv: *const u8) -> RlsResult<()> {
        unsafe { EVP_EncryptInit_ex(self.ctx.as_mut_ptr(), self.evp_cipher.as_boring(), null_mut(), key, iv) }.ok(RlsError::CipherCryptError)?;
        unsafe { EVP_CIPHER_CTX_set_padding(self.ctx.as_mut_ptr(), 0) };
        Ok(())
    }

    pub(crate) fn init_decrypt(&self, key: *const u8, iv: *const u8) -> RlsResult<()> {
        unsafe { EVP_DecryptInit_ex(self.ctx.as_mut_ptr(), self.evp_cipher.as_boring(), null_mut(), key, iv) }.ok(RlsError::CipherCryptError)?;
        unsafe { EVP_CIPHER_CTX_set_padding(self.ctx.as_mut_ptr(), 0) };
        Ok(())
    }

    pub(crate) fn encrypt_update(&self, context: *const u8, len: usize, out: *mut u8) -> RlsResult<usize> {
        let mut out_len = 0;
        unsafe {
            EVP_EncryptUpdate(
                self.ctx.as_mut_ptr(),
                out,
                &mut out_len,
                context,
                len as i32)
        }.ok(RlsError::CipherEncryptError)?;
        Ok(out_len as usize)
    }

    pub(crate) fn encrypt_finalize(&self, out: *mut u8) -> RlsResult<usize> {
        let mut final_len = 0;
        unsafe {
            EVP_EncryptFinal_ex(
                self.ctx.as_mut_ptr(),
                out,
                &mut final_len,
            )
        }.ok(RlsError::CipherEncryptError)?;
        Ok(final_len as usize)
    }

    pub(crate) fn decrypt_update(&self, context: *const u8, len: usize, out: *mut u8) -> RlsResult<usize> {
        let mut out_len = 0;
        unsafe {
            EVP_DecryptUpdate(
                self.ctx.as_mut_ptr(),
                out,
                &mut out_len,
                context,
                len as i32,
            )
        }.ok(RlsError::CipherDecryptError)?;
        Ok(out_len as usize)
    }

    pub(crate) fn decrypt_finalize(&self, out: *mut u8) -> RlsResult<usize> {
        let mut final_len = 0;
        unsafe {
            EVP_DecryptFinal_ex(
                self.ctx.as_mut_ptr(),
                out,
                &mut final_len,
            )
        }.ok(RlsError::CipherDecryptError)?;
        Ok(final_len as usize)
    }
}

pub fn en_b64<T: Into<Vec<u8>>>(typ: CipherType, key: T, iv: Option<T>, data: impl AsRef<[u8]>) -> RlsResult<String> {
    let cipher = Cipher::new(typ).with_secret_key(key, iv);
    let en_bs = cipher.encrypt(data)?;
    Ok(base64::b64encode(en_bs)?)
}

pub fn de_b64<T: Into<Vec<u8>>>(typ: CipherType, key: T, iv: Option<T>, data: impl AsRef<[u8]>) -> RlsResult<Vec<u8>> {
    let de_b64 = base64::b64decode(data)?;
    let cipher = Cipher::new(typ).with_secret_key(key, iv);
    cipher.decrypt(de_b64)
}

pub fn en_hex<T: Into<Vec<u8>>>(typ: CipherType, key: T, iv: Option<T>, data: impl AsRef<[u8]>) -> RlsResult<String> {
    let cipher = Cipher::new(typ).with_secret_key(key, iv);
    let en_bs = cipher.encrypt(data)?;
    Ok(hex::encode(en_bs))
}

pub fn de_hex<T: Into<Vec<u8>>>(typ: CipherType, key: T, iv: Option<T>, data: impl AsRef<[u8]>) -> RlsResult<Vec<u8>> {
    let de_hex = hex::decode(data)?;
    let cipher = Cipher::new(typ).with_secret_key(key, iv);
    cipher.decrypt(de_hex)
}