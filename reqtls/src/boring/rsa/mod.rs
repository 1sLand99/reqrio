pub(super) mod bindings;

use std::path::Path;
use crate::boring::bindings::*;
use crate::boring::BoringResExt;
use crate::error::RlsResult;
use crate::RlsError;
use bindings::*;
use std::ptr::null_mut;
use std::{fs, slice};
pub use certificate::Certificate;
use crate::boring::ffi::{BufPtr, CPointer};
use crate::RlsError::WritePubKeyError;

mod certificate;

pub struct RsaKey(CPointer<EVP_PKEY>);

impl RsaKey {
    pub fn none() -> RsaKey {
        RsaKey(CPointer::nullptr())
    }
    pub fn gen_new_key(bits: i32) -> RlsResult<RsaKey> {
        let mut rsa = CPointer::new(unsafe { RSA_new() });
        if rsa.is_null() { return Err(RlsError::RsaNewError); }
        let e = CPointer::new(unsafe { BN_new() });
        if e.is_null() { return Err(RlsError::BnNewError); };
        unsafe { BN_set_word(e.as_mut_ptr(), RSA_F4 as u64) }.ok(RlsError::BnSetWordError)?;
        unsafe { RSA_generate_key_ex(rsa.as_mut_ptr(), bits, e.as_mut_ptr(), null_mut()) }.ok(RlsError::RsaGenKeyError)?;
        let pkey = CPointer::new(unsafe { EVP_PKEY_new() });
        if pkey.is_null() { return Err(RlsError::PkeyNewError); };
        unsafe { EVP_PKEY_assign_RSA(pkey.as_mut_ptr(), rsa.as_mut_ptr()) }.ok(RlsError::PkeyAssignError)?;
        rsa.disable_auto_free();
        Ok(RsaKey(pkey))
    }

    pub fn to_pri_pem(&self) -> RlsResult<String> {
        let bio = CPointer::new(unsafe { BIO_new(BIO_s_mem()) });
        if bio.is_null() { return Err(RlsError::BioNewError); }
        unsafe {
            PEM_write_bio_PrivateKey(
                bio.as_mut_ptr(),
                self.0.as_mut_ptr(),
                null_mut(),
                null_mut(),
                0,
                None,
                null_mut(),
            )
        }.ok(RlsError::WritePriKeyError)?;
        let mut data = null_mut();
        let len = unsafe { BIO_get_mem_data(bio.as_mut_ptr(), &mut data) };
        let out = unsafe { slice::from_raw_parts(data as *const u8, len as usize) }.to_vec();
        Ok(String::from_utf8(out)?)
    }

    pub fn to_pub_pem(&self) -> RlsResult<String> {
        let bio = CPointer::new(unsafe { BIO_new(BIO_s_mem()) });
        if bio.is_null() { return Err(RlsError::BioNewError); }
        unsafe { PEM_write_bio_PUBKEY(bio.as_mut_ptr(), self.0.as_mut_ptr()) }.ok(WritePubKeyError)?;
        let mut data = null_mut();
        let len = unsafe { BIO_get_mem_data(bio.as_mut_ptr(), &mut data) };
        let out = unsafe { slice::from_raw_parts(data as *const u8, len as usize) }.to_vec();
        Ok(String::from_utf8(out)?)
    }

    pub fn to_pri_der(&self) -> BufPtr {
        let mut buf = BufPtr::nullptr();
        let len = unsafe { i2d_PrivateKey(self.0.as_ptr(), buf.ptr_mut()) };
        buf.set_len(len as usize);
        buf
    }

    pub fn to_pub_der(&self) -> BufPtr {
        let mut buf = BufPtr::nullptr();
        let len = unsafe { i2d_PUBKEY(self.0.as_ptr(), buf.ptr_mut()) };
        buf.set_len(len as usize);
        buf
    }

    pub fn from_pri_pem(pem: impl AsRef<[u8]>) -> RlsResult<RsaKey> {
        let bio = CPointer::new(unsafe { BIO_new_mem_buf(pem.as_ref().as_ptr() as *const _, pem.as_ref().len() as isize) });
        if bio.is_null() { return Err(RlsError::BioNewError); }
        let pkey = CPointer::new(unsafe { PEM_read_bio_PrivateKey(bio.as_mut_ptr(), null_mut(), None, null_mut()) });
        if pkey.is_null() { return Err(RlsError::BioNewError); }
        Ok(RsaKey(pkey))
    }

    pub fn from_pri_pem_file(pem_file: impl AsRef<Path>) -> RlsResult<RsaKey> {
        let pem = fs::read(pem_file)?;
        RsaKey::from_pri_pem(pem)
    }

    pub fn from_pub_pem(pem: impl AsRef<[u8]>) -> RlsResult<RsaKey> {
        let bio = CPointer::new(unsafe { BIO_new_mem_buf(pem.as_ref().as_ptr() as *const _, pem.as_ref().len() as isize) });
        if bio.is_null() { return Err(RlsError::BioNewError); }
        let pkey = CPointer::new(unsafe { PEM_read_bio_PUBKEY(bio.as_mut_ptr(), null_mut(), None, null_mut()) });
        if pkey.is_null() { return Err(RlsError::PkeyNewError); };
        Ok(RsaKey(pkey))
    }

    pub fn from_pri_der(der: impl AsRef<[u8]>) -> RlsResult<RsaKey> {
        let pkey = CPointer::new(unsafe { d2i_AutoPrivateKey(null_mut(), &mut der.as_ref().as_ptr(), (der.as_ref().len() as u16).into()) });
        if pkey.is_null() { return Err(RlsError::PkeyNewError); };
        Ok(RsaKey(pkey))
    }

    pub fn from_pub_der(der: impl AsRef<[u8]>) -> RlsResult<RsaKey> {
        let pkey = CPointer::new(unsafe { d2i_PUBKEY(null_mut(), &mut der.as_ref().as_ptr(), (der.as_ref().len() as u16).into()) });
        if pkey.is_null() { return Err(RlsError::PkeyNewError); };
        Ok(RsaKey(pkey))
    }

    pub fn new(pkey: CPointer<EVP_PKEY>) -> RsaKey {
        RsaKey(pkey)
    }

    pub fn pkey(&self) -> &CPointer<EVP_PKEY> {
        &self.0
    }
}


pub struct RsaCipher {
    ctx: CPointer<EVP_PKEY_CTX>,
}

impl RsaCipher {
    pub fn new(key: &CPointer<EVP_PKEY>) -> RlsResult<RsaCipher> {
        let ctx = CPointer::new(unsafe { EVP_PKEY_CTX_new(key.as_mut_ptr(), null_mut()) });
        if ctx.is_null() { return Err(RlsError::RsaNewError); }
        Ok(RsaCipher {
            ctx,
        })
    }
    pub fn from_rsa_key(key: &RsaKey) -> RlsResult<RsaCipher> {
        RsaCipher::new(&key.0)
    }

    pub fn encrypt(&self, data: impl AsRef<[u8]>, oaep: bool) -> RlsResult<Vec<u8>> {
        unsafe { EVP_PKEY_encrypt_init(self.ctx.as_mut_ptr()) }.ok(RlsError::InitEncryptError)?;
        let padding = if oaep { RSA_PKCS1_OAEP_PADDING } else { RSA_PKCS1_PADDING };
        unsafe { EVP_PKEY_CTX_set_rsa_padding(self.ctx.as_mut_ptr(), padding) }.ok(RlsError::RsaSetPaddingError)?;
        let mut out_len = 0;
        unsafe {
            EVP_PKEY_encrypt(
                self.ctx.as_mut_ptr(),
                null_mut(),
                &mut out_len,
                data.as_ref().as_ptr(),
                data.as_ref().len(),
            )
        }.ok(RlsError::PkeyEncryptError)?;
        let mut out = vec![0u8; out_len];
        unsafe {
            EVP_PKEY_encrypt(
                self.ctx.as_mut_ptr(),
                out.as_mut_ptr(),
                &mut out_len,
                data.as_ref().as_ptr(),
                data.as_ref().len(),
            )
        }.ok(RlsError::PkeyEncryptError)?;
        Ok(out)
    }

    pub fn decrypt(&self, data: impl AsRef<[u8]>, oaep: bool) -> RlsResult<Vec<u8>> {
        unsafe { EVP_PKEY_decrypt_init(self.ctx.as_mut_ptr()) }.ok(RlsError::InitDecryptError)?;
        let padding = if oaep { RSA_PKCS1_OAEP_PADDING } else { RSA_PKCS1_PADDING };
        unsafe { EVP_PKEY_CTX_set_rsa_padding(self.ctx.as_mut_ptr(), padding) }.ok(RlsError::RsaSetPaddingError)?;
        let mut out_len = data.as_ref().len();
        let mut out = vec![0u8; data.as_ref().len()];
        unsafe {
            EVP_PKEY_decrypt(
                self.ctx.as_mut_ptr(),
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

#[cfg(test)]
mod tests {
    use crate::{RsaCipher, RsaKey};

    #[test]
    fn test_rsa() {
        let key = RsaKey::gen_new_key(2048).unwrap();
        println!("{}", key.to_pri_pem().unwrap());
        println!("{}", key.to_pub_pem().unwrap());
        println!("{:?}", key.to_pri_der());
        println!("{:?}", key.to_pub_der());
        let nkey = RsaKey::from_pub_der(key.to_pub_der().as_slice()).unwrap();
        let rsa = RsaCipher::from_rsa_key(&nkey).unwrap();
        let encrypted = rsa.encrypt("adsdfds", true).unwrap();
        println!("{} {:?}", encrypted.len(), encrypted);

        let nkey = RsaKey::from_pri_der(key.to_pri_der().as_slice()).unwrap();
        let rsa = RsaCipher::from_rsa_key(&nkey).unwrap();
        let decrypted = rsa.decrypt(encrypted.as_slice(), true).unwrap();
        println!("{} {:?}", decrypted.len(), decrypted);
    }
}