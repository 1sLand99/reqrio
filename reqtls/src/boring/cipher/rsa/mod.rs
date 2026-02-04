mod bindings;
use crate::boring::bindings::*;
use crate::boring::cipher::BoringResExt;
use crate::error::RlsResult;
use crate::RlsError;
use bindings::*;
use std::ptr::null_mut;
use std::slice;

pub struct RsaKey(*mut EVP_PKEY);

impl RsaKey {
    pub fn gen_new_key(bits: i32) -> RlsResult<RsaKey> {
        let rsa = unsafe { RSA_new() };
        if rsa.is_null() { return Err(RlsError::RsaNewError); }
        let e = unsafe { BN_new() };
        if e.is_null() {
            unsafe { RSA_free(rsa) }
            return Err(RlsError::BnNewError);
        };
        let ret = unsafe { BN_set_word(e, RSA_F4 as u64) };
        if ret != 1 {
            unsafe {
                RSA_free(rsa);
                BN_free(e);
            }
            return Err(RlsError::BnSetWordError);
        }
        let ret = unsafe { RSA_generate_key_ex(rsa, bits, e, null_mut()) };
        if ret != 1 {
            unsafe {
                RSA_free(rsa);
                BN_free(e);
            }
            return Err(RlsError::RsaGenKeyError);
        }
        let pkey = unsafe { EVP_PKEY_new() };
        if pkey.is_null() {
            unsafe {
                RSA_free(rsa);
                BN_free(e);
            }
            return Err(RlsError::PkeyNewError);
        };
        let ret = unsafe { EVP_PKEY_assign_RSA(pkey, rsa) };
        unsafe { BN_free(e); }
        if ret != 1 {
            unsafe { RSA_free(rsa) };
            return Err(RlsError::PkeyAssignError);
        }
        Ok(RsaKey(pkey))
    }

    pub fn to_pri_pem(&self) -> RlsResult<String> {
        let bio = unsafe { BIO_new(BIO_s_mem()) };
        if bio.is_null() { return Err(RlsError::BioNewError); }
        let ret = unsafe {
            PEM_write_bio_PrivateKey(
                bio,
                self.0,
                null_mut(),
                null_mut(),
                0,
                None,
                null_mut(),
            )
        };
        if ret != 1 {
            unsafe { BIO_free(bio) };
            return Err(RlsError::WritePriKeyError);
        }
        let mut data = null_mut();
        let len = unsafe { BIO_get_mem_data(bio, &mut data) };
        let out = unsafe { slice::from_raw_parts(data as *const u8, len as usize) }.to_vec();
        unsafe { BIO_free(bio) };
        Ok(String::from_utf8(out)?)
    }

    pub fn to_pub_pem(&self) -> RlsResult<String> {
        let bio = unsafe { BIO_new(BIO_s_mem()) };
        if bio.is_null() { return Err(RlsError::BioNewError); }
        let ret = unsafe { PEM_write_bio_PUBKEY(bio, self.0) };
        if ret != 1 {
            unsafe { BIO_free(bio) };
            return Err(RlsError::WritePubKeyError);
        }
        let mut data = null_mut();
        let len = unsafe { BIO_get_mem_data(bio, &mut data) };
        let out = unsafe { slice::from_raw_parts(data as *const u8, len as usize) }.to_vec();
        unsafe { BIO_free(bio) };
        Ok(String::from_utf8(out)?)
    }

    pub fn to_pri_der(&self) -> &[u8] {
        let mut buf = null_mut();
        let len = unsafe { i2d_PrivateKey(self.0, &mut buf) };
        unsafe { slice::from_raw_parts(buf, len as usize) }
    }

    pub fn to_pub_der(&self) -> &[u8] {
        let mut buf = null_mut();
        let len = unsafe { i2d_PUBKEY(self.0, &mut buf) };
        unsafe { slice::from_raw_parts(buf, len as usize) }
    }

    pub fn from_pri_pem(pem: impl AsRef<[u8]>) -> RlsResult<RsaKey> {
        let bio = unsafe { BIO_new_mem_buf(pem.as_ref().as_ptr() as *const _, pem.as_ref().len() as isize) };
        if bio.is_null() { return Err(RlsError::BioNewError); }
        let pkey = unsafe { PEM_read_bio_PrivateKey(bio, null_mut(), None, null_mut()) };
        unsafe { BIO_free(bio) };
        if pkey.is_null() { return Err(RlsError::BioNewError); }
        Ok(RsaKey(pkey))
    }

    pub fn from_pub_pem(pem: impl AsRef<[u8]>) -> RlsResult<RsaKey> {
        let bio = unsafe { BIO_new_mem_buf(pem.as_ref().as_ptr() as *const _, pem.as_ref().len() as isize) };
        if bio.is_null() { return Err(RlsError::BioNewError); }
        let pkey = unsafe { PEM_read_bio_PUBKEY(bio, null_mut(), None, null_mut()) };
        unsafe { BIO_free(bio) };
        if pkey.is_null() { return Err(RlsError::PkeyNewError); };
        Ok(RsaKey(pkey))
    }

    pub fn from_pri_der(der: impl AsRef<[u8]>) -> RlsResult<RsaKey> {
        let pkey = unsafe { d2i_AutoPrivateKey(null_mut(), &mut der.as_ref().as_ptr(), (der.as_ref().len() as u16).into()) };
        if pkey.is_null() { return Err(RlsError::PkeyNewError); };
        Ok(RsaKey(pkey))
    }

    pub fn from_pub_der(der: impl AsRef<[u8]>) -> RlsResult<RsaKey> {
        let pkey = unsafe { d2i_PUBKEY(null_mut(), &mut der.as_ref().as_ptr(), (der.as_ref().len() as u16).into()) };
        if pkey.is_null() { return Err(RlsError::PkeyNewError); };
        Ok(RsaKey(pkey))
    }

    pub fn pkey(&self) -> *mut EVP_PKEY {
        self.0
    }
}

impl Drop for RsaKey {
    fn drop(&mut self) {
        unsafe { EVP_PKEY_free(self.0); }
    }
}


pub struct RsaCipher {
    ctx: *mut EVP_PKEY_CTX,
    _key: RsaKey,
}

impl RsaCipher {
    pub fn from_key(key: RsaKey) -> RlsResult<RsaCipher> {
        let ctx = unsafe { EVP_PKEY_CTX_new(key.0, null_mut()) };
        if ctx.is_null() { return Err(RlsError::RsaNewError); }
        Ok(RsaCipher {
            ctx,
            _key: key,
        })
    }

    pub fn encrypt(&self, data: impl AsRef<[u8]>, oaep: bool) -> RlsResult<Vec<u8>> {
        unsafe { EVP_PKEY_encrypt_init(self.ctx) }.ok(RlsError::InitEncryptError)?;
        let padding = if oaep { RSA_PKCS1_OAEP_PADDING } else { RSA_PKCS1_PADDING };
        unsafe { EVP_PKEY_CTX_set_rsa_padding(self.ctx, padding) }.ok(RlsError::RsaSetPaddingError)?;
        let mut out_len = 0;
        unsafe {
            EVP_PKEY_encrypt(
                self.ctx,
                null_mut(),
                &mut out_len,
                data.as_ref().as_ptr(),
                data.as_ref().len(),
            )
        }.ok(RlsError::PkeyEncryptError)?;
        let mut out = vec![0u8; out_len];
        unsafe {
            EVP_PKEY_encrypt(
                self.ctx,
                out.as_mut_ptr(),
                &mut out_len,
                data.as_ref().as_ptr(),
                data.as_ref().len(),
            )
        }.ok(RlsError::PkeyEncryptError)?;
        Ok(out)
    }

    pub fn decrypt(&self, data: impl AsRef<[u8]>, oaep: bool) -> RlsResult<Vec<u8>> {
        unsafe { EVP_PKEY_decrypt_init(self.ctx) }.ok(RlsError::InitDecryptError)?;
        let padding = if oaep { RSA_PKCS1_OAEP_PADDING } else { RSA_PKCS1_PADDING };
        unsafe { EVP_PKEY_CTX_set_rsa_padding(self.ctx, padding) }.ok(RlsError::RsaSetPaddingError)?;
        let mut out_len = data.as_ref().len();
        let mut out = vec![0u8; data.as_ref().len()];
        unsafe {
            EVP_PKEY_decrypt(
                self.ctx,
                out.as_mut_ptr(),
                &mut out_len,
                data.as_ref().as_ptr(),
                data.as_ref().len(),
            )
        }.ok(RlsError::PkeyDecryptError)?;
        out.truncate(out_len);
        Ok(out)
    }
}

impl Drop for RsaCipher {
    fn drop(&mut self) {
        unsafe { EVP_PKEY_CTX_free(self.ctx) }
    }
}

#[cfg(test)]
mod tests {
    use crate::boring::cipher::rsa::{RsaCipher, RsaKey};

    #[test]
    fn test_rsa() {
        let key = RsaKey::gen_new_key(2048).unwrap();
        println!("{}", key.to_pri_pem().unwrap());
        println!("{}", key.to_pub_pem().unwrap());
        println!("{:?}", key.to_pri_der());
        println!("{:?}", key.to_pub_der());
        let nkey = RsaKey::from_pub_der(key.to_pub_der()).unwrap();
        let rsa = RsaCipher::from_key(nkey).unwrap();
        let encrypted = rsa.encrypt("adsdfds", true).unwrap();
        println!("{} {:?}", encrypted.len(), encrypted);

        let nkey = RsaKey::from_pri_der(key.to_pri_der()).unwrap();
        let rsa = RsaCipher::from_key(nkey).unwrap();
        let decrypted = rsa.decrypt(encrypted.as_slice(), true).unwrap();
        println!("{} {:?}", decrypted.len(), decrypted);
    }
}