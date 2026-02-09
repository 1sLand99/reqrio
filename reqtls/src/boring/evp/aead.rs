use crate::boring::CryptParam;
use crate::error::RlsResult;
use crate::extend::Aead;
use crate::RlsError;
use std::mem::MaybeUninit;
use std::ptr::null_mut;
use crate::boring::bindings::*;

pub struct AeadCrypto {
    ctx: MaybeUninit<EVP_AEAD_CTX>,
}

impl AeadCrypto {
    pub fn new(aead: &Aead, key: &[u8]) -> RlsResult<AeadCrypto> {
        let evp_aead = match aead {
            Aead::AES_128_GCM => unsafe { EVP_aead_aes_128_gcm() },
            Aead::AES_256_GCM => unsafe { EVP_aead_aes_256_gcm() }
            Aead::ChaCha20_POLY1305 => unsafe { EVP_aead_chacha20_poly1305() }
            _ => return Err("not aead,but in aead".into())
        };
        let mut ctx = MaybeUninit::zeroed();
        let ok = unsafe { EVP_AEAD_CTX_init(ctx.as_mut_ptr(), evp_aead, key.as_ptr(), key.len(), EVP_AEAD_DEFAULT_TAG_LENGTH as usize, null_mut()) };
        if ok != 1 { return Err(RlsError::AeadCryptError); }
        Ok(AeadCrypto { ctx })
    }

    pub fn encrypt(&self, param: CryptParam) -> RlsResult<usize> {
        let mut out_len = 0;
        let ok = unsafe {
            EVP_AEAD_CTX_seal(
                self.ctx.as_ptr(),
                param.payload.encrypting_out(param.aead).as_mut_ptr(),
                &mut out_len,
                param.payload.encrypting_out(param.aead).len(),
                param.nonce.as_ptr(),
                param.nonce.len(),
                param.payload.encrypting_in(param.aead).as_ptr(),
                param.payload.encrypting_in(param.aead).len(),
                param.aad.as_ptr(),
                param.aad.len(),
            )
        };
        let len = out_len + param.aead.explicit_len();
        if ok != 1 { Err(RlsError::AeadEncryptError) } else { Ok(len) }
    }

    pub fn decrypt(&self, param: CryptParam) -> RlsResult<usize> {
        let mut out_len = 0usize;
        let ok = unsafe {
            EVP_AEAD_CTX_open(
                self.ctx.as_ptr(),
                param.payload.decrypting_payload(param.aead).as_mut_ptr(),
                &mut out_len,
                param.payload.decrypting_payload(param.aead).len() - 16,
                param.nonce.as_ptr(),
                param.nonce.len(),
                param.payload.decrypting_payload(param.aead).as_ptr(),
                param.payload.decrypting_payload(param.aead).len(),
                param.aad.as_ptr(),
                param.aad.len(),
            )
        };
        if ok != 1 { Err(RlsError::AeadDecryptError) } else { Ok(out_len) }
    }
}

impl Drop for AeadCrypto {
    fn drop(&mut self) {
        unsafe { EVP_AEAD_CTX_cleanup(self.ctx.as_mut_ptr()) }
    }
}

unsafe impl Send for AeadCrypto {}

unsafe impl Sync for AeadCrypto {}