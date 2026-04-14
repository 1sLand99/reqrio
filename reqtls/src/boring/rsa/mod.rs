use crate::boring::bindings::*;
use crate::boring::BoringResExt;
use crate::error::RlsResult;
use crate::ffi::CPointer;
use crate::RlsError;
use bindings::*;
use std::ptr::null_mut;
pub use key::RsaKey;
pub use padding::RsaPadding;

pub mod certificate;
#[allow(dead_code)]
pub(crate) mod bindings;
mod key;
mod padding;

pub struct RsaCipher {
    ctx: CPointer<EVP_PKEY_CTX>,
    padding: RsaPadding,
}

impl RsaCipher {
    pub fn new(key: &CPointer<EVP_PKEY>) -> RlsResult<RsaCipher> {
        let ctx = CPointer::new(unsafe { EVP_PKEY_CTX_new(key.as_mut_ptr(), null_mut()) });
        if ctx.is_null() { return Err(RlsError::RsaNewError); }
        Ok(RsaCipher {
            ctx,
            padding: RsaPadding::Pkcs1,
        })
    }
    pub fn from_rsa_key(key: &RsaKey) -> RlsResult<RsaCipher> {
        RsaCipher::new(key.pkey())
    }

    pub fn encrypt(&self, data: impl AsRef<[u8]>) -> RlsResult<Vec<u8>> {
        unsafe { EVP_PKEY_encrypt_init(self.ctx.as_mut_ptr()) }.ok(RlsError::InitEncryptError)?;
        unsafe { EVP_PKEY_CTX_set_rsa_padding(self.ctx.as_mut_ptr(), self.padding.as_i32()) }.ok(RlsError::RsaSetPaddingError)?;
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

    pub fn decrypt(&self, data: impl AsRef<[u8]>) -> RlsResult<Vec<u8>> {
        unsafe { EVP_PKEY_decrypt_init(self.ctx.as_mut_ptr()) }.ok(RlsError::InitDecryptError)?;
        unsafe { EVP_PKEY_CTX_set_rsa_padding(self.ctx.as_mut_ptr(), self.padding.as_i32()) }.ok(RlsError::RsaSetPaddingError)?;
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
        let nkey = RsaKey::from_pub_der(key.to_pub_der().unwrap().as_slice()).unwrap();
        let rsa = RsaCipher::from_rsa_key(&nkey).unwrap();
        let encrypted = rsa.encrypt("adsdfds").unwrap();
        println!("{} {:?}", encrypted.len(), encrypted);

        let nkey = RsaKey::from_pri_der(key.to_pri_der().unwrap().as_slice()).unwrap();
        let rsa = RsaCipher::from_rsa_key(&nkey).unwrap();
        let decrypted = rsa.decrypt(encrypted.as_slice()).unwrap();
        println!("{} {:?}", decrypted.len(), decrypted);
    }
}