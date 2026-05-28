use super::super::Padding;
use super::CipherType;
use crate::boring::bindings::*;
use crate::boring::BoringResExt;
use crate::error::RlsResult;
use crate::ffi::CPointer;
use crate::base64;
use std::ptr::{null, null_mut};


#[derive(Debug)]
pub enum CipherError {
    NewCipherCtx,
    CipherReset,
    CipherInit,
    SetKeyLen,
    SetPadding,
    CipherUpdate,
    CipherFinalize,
    InvalidMac,
}

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

    pub fn sm4_ecb() -> Cipher { Cipher::new(CipherType::SM4_ECB) }

    pub fn sm4_cbc() -> Cipher { Cipher::new(CipherType::SM4_CBC) }

    pub fn with_secret_key<T: Into<Vec<u8>>>(mut self, key: T, iv: Option<T>) -> Self {
        self.set_secret_key(key, iv);
        self
    }

    pub fn set_secret_key<T: Into<Vec<u8>>>(&mut self, key: T, iv: Option<T>) {
        self.key = key.into();
        self.iv = iv.map(|iv| iv.into()).unwrap_or(vec![]);
    }

    pub fn encrypt(&self, context: impl AsRef<[u8]>) -> Result<Vec<u8>, CipherError> {
        if self.ctx.is_null() { return Err(CipherError::NewCipherCtx); }
        let mut out = vec![0; context.as_ref().len() + 16];
        let padding = if !matches!(self.evp_cipher, CipherType::RC4) { self.padding.add_padding(context.as_ref()) } else { vec![] };
        let iv = if self.iv.is_empty() { null() } else { self.iv.as_ptr() };
        self.init_cipher(iv, 1)?;
        let ptr = context.as_ref().as_ptr();
        let out_ptr = out.as_mut_ptr();
        let block_len = self.update(ptr, context.as_ref().len(), out_ptr)?;
        let out_ptr = unsafe { out_ptr.add(block_len) };
        let padding_len = self.update(padding.as_ptr(), padding.len(), out_ptr)?;
        let out_ptr = unsafe { out_ptr.add(padding_len) };
        let final_len = self.finalize(out_ptr)?;
        out.truncate(block_len + padding_len + final_len);
        Ok(out)
    }

    pub fn decrypt(&self, context: impl Into<Vec<u8>>) -> Result<Vec<u8>, CipherError> {
        if self.ctx.is_null() { return Err(CipherError::NewCipherCtx); }
        let iv = if self.iv.is_empty() { null() } else { self.iv.as_ptr() };
        self.init_cipher(iv, 0)?;
        let mut context = context.into();
        let ptr = context.as_ptr();
        let out = context.as_mut_ptr();
        let out_len = self.update(ptr, context.len(), out)?;
        let out = unsafe { out.add(out_len) };
        let final_len = self.finalize(out)?;
        context.truncate(out_len + final_len);
        if !matches!(self.evp_cipher, CipherType::RC4) { self.padding.remove_padding(&mut context); }
        Ok(context)
    }

    pub(crate) fn init_cipher(&self, iv: *const u8, enc: i32) -> Result<(), CipherError> {
        unsafe { EVP_CIPHER_CTX_reset(self.ctx.as_mut_ptr()) }.ok(CipherError::CipherReset)?;
        unsafe { EVP_CipherInit_ex(self.ctx.as_mut_ptr(), self.evp_cipher.as_boring(), null_mut(), null_mut(), null_mut(), enc) }.ok(CipherError::CipherInit)?;
        unsafe { EVP_CIPHER_CTX_set_key_length(self.ctx.as_mut_ptr(), self.key.len() as u32) }.ok(CipherError::SetKeyLen)?;
        let key = self.key.as_ptr();
        unsafe { EVP_CipherInit_ex(self.ctx.as_mut_ptr(), null_mut(), null_mut(), key, iv, enc) }.ok(CipherError::CipherInit)?;
        unsafe { EVP_CIPHER_CTX_set_padding(self.ctx.as_mut_ptr(), 0) }.ok(CipherError::SetPadding)
    }

    pub(crate) fn update(&self, context: *const u8, len: usize, out: *mut u8) -> Result<usize, CipherError> {
        let mut out_len = 0;
        unsafe {
            EVP_CipherUpdate(
                self.ctx.as_mut_ptr(),
                out,
                &mut out_len,
                context,
                len as i32,
            )
        }.ok(CipherError::CipherUpdate)?;
        Ok(out_len as usize)
    }

    pub(crate) fn finalize(&self, out: *mut u8) -> Result<usize, CipherError> {
        let mut final_len = 0;
        unsafe { EVP_CipherFinal_ex(self.ctx.as_mut_ptr(), out, &mut final_len) }.ok(CipherError::CipherFinalize)?;
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
    Ok(cipher.decrypt(de_b64)?)
}

pub fn en_hex<T: Into<Vec<u8>>>(typ: CipherType, key: T, iv: Option<T>, data: impl AsRef<[u8]>) -> RlsResult<String> {
    let cipher = Cipher::new(typ).with_secret_key(key, iv);
    let en_bs = cipher.encrypt(data)?;
    Ok(hex::encode(en_bs))
}

pub fn de_hex<T: Into<Vec<u8>>>(typ: CipherType, key: T, iv: Option<T>, data: impl AsRef<[u8]>) -> RlsResult<Vec<u8>> {
    let de_hex = hex::decode(data)?;
    let cipher = Cipher::new(typ).with_secret_key(key, iv);
    Ok(cipher.decrypt(de_hex)?)
}


#[cfg(test)]
mod tests {
    use crate::Cipher;

    #[test]
    fn test_cipher() {
        let cipher = Cipher::aes_128_cbc().with_secret_key("1234567812345678", Some("1234567812345678"));
        let en = cipher.encrypt(b"hello world").unwrap();
        assert_eq!(en, [107, 100, 169, 51, 126, 231, 189, 86, 45, 6, 117, 71, 162, 117, 252, 235]);
        let de = cipher.decrypt(en).unwrap();
        assert_eq!(de, b"hello world");

        let cipher = Cipher::aes_192_cbc().with_secret_key("123456781234567812345678", Some("1234567812345678"));
        let en = cipher.encrypt(b"hello world").unwrap();
        assert_eq!(en, [112, 230, 39, 80, 184, 157, 131, 154, 85, 102, 84, 183, 111, 20, 203, 165]);
        let de = cipher.decrypt(en).unwrap();
        assert_eq!(de, b"hello world");

        let cipher = Cipher::aes_256_cbc().with_secret_key("12345678123456781234567812345678", Some("1234567812345678"));
        let en = cipher.encrypt(b"hello world").unwrap();
        assert_eq!(en, [110, 146, 35, 67, 140, 149, 192, 43, 116, 68, 194, 52, 36, 51, 159, 76]);
        let de = cipher.decrypt(en).unwrap();
        assert_eq!(de, b"hello world");

        let cipher = Cipher::rc4().with_secret_key("7d1a840419e1648c4e247b70f4a1e472", None);
        let res = cipher.decrypt([35, 35, 52, 190, 118, 125, 64, 163, 60, 89, 220, 195, 147, 90, 228, 21]).unwrap();
        assert_eq!(res, [112, 107, 105, 73, 79, 122, 72, 108, 69, 84, 76, 80, 100, 69, 85, 113]);

        let key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10];
        let cipher = Cipher::sm4_ecb().with_secret_key(&key, None);
        let data = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10];
        let en = cipher.encrypt(data).unwrap();
        assert_eq!(&en[..16], [104, 30, 223, 52, 210, 6, 150, 94, 134, 179, 233, 79, 83, 110, 66, 70]);
        let de = cipher.decrypt(en).unwrap();
        assert_eq!(de, data);

        let cipher = Cipher::sm4_cbc().with_secret_key(&key, Some(&key));
        let en = cipher.encrypt(data).unwrap();
        assert_eq!(en, [38, 119, 244, 107, 9, 193, 34, 204, 151, 85, 51, 16, 91, 212, 162, 42, 59, 136, 14, 104, 103, 119, 37, 34, 174, 85, 210, 240, 174, 116, 120, 174]);
        let de = cipher.decrypt(en).unwrap();
        assert_eq!(de, data);
    }
}