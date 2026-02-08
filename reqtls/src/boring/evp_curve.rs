use crate::error::RlsResult;
use crate::RlsError;
use super::bindings::*;
use std::ptr::null_mut;

pub struct EvpCurve {
    evp_key: *mut EVP_PKEY,
    pub_key: Vec<u8>,
    nid: i32,
    secret: usize,
}


impl EvpCurve {
    pub fn new_x25519() -> RlsResult<EvpCurve> {
        EvpCurve::new(EVP_PKEY_X25519, 32, 32)
    }

    fn new(nid: i32, mut pub_len: usize, secret_len: usize) -> RlsResult<EvpCurve> {
        let ctx = unsafe { EVP_PKEY_CTX_new_id(nid, null_mut()) };
        if ctx.is_null() {
            return Err(RlsError::InitEvpPKeyCtxError);
        }
        let ret = unsafe { EVP_PKEY_keygen_init(ctx) };
        if ret != 1 {
            unsafe { EVP_PKEY_CTX_free(ctx); }
            return Err(RlsError::InitKeygenError);
        }
        let mut pkey = null_mut();
        let ret = unsafe { EVP_PKEY_keygen(ctx, &mut pkey) };
        unsafe { EVP_PKEY_CTX_free(ctx); }
        if ret != 1 {
            return Err(RlsError::KeyGenError);
        }
        let mut pub_key = vec![0; pub_len];
        let ret = unsafe { EVP_PKEY_get_raw_public_key(pkey, pub_key.as_mut_ptr(), &mut pub_len) };
        if ret != 1 { return Err(RlsError::GetPubKeyError); }
        Ok(EvpCurve {
            evp_key: pkey,
            pub_key,
            secret: secret_len,
            nid,
        })
    }

    pub fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    pub fn diffie_hellman(&mut self, pub_key: impl AsRef<[u8]>) -> RlsResult<Vec<u8>> {
        let pub_key = unsafe {
            EVP_PKEY_new_raw_public_key(
                self.nid,
                null_mut(),
                pub_key.as_ref().as_ptr(),
                pub_key.as_ref().len(),
            )
        };
        if pub_key.is_null() {
            return Err(RlsError::NewPublicKeyError);
        }
        let ctx = unsafe { EVP_PKEY_CTX_new(self.evp_key, null_mut()) };
        if ctx.is_null() {
            unsafe { EVP_PKEY_free(pub_key); }
            return Err(RlsError::InitEvpPKeyCtxError);
        }
        let ret = unsafe { EVP_PKEY_derive_init(ctx) };
        if ret != 1 {
            unsafe { EVP_PKEY_free(pub_key); }
            unsafe { EVP_PKEY_CTX_free(ctx); }
            return Err(RlsError::InitDeriveError);
        }
        let ret = unsafe { EVP_PKEY_derive_set_peer(ctx, pub_key) };
        if ret != 1 {
            unsafe { EVP_PKEY_free(pub_key); }
            unsafe { EVP_PKEY_CTX_free(ctx); }
            return Err(RlsError::SetPeerDeriveError);
        }
        let mut secret = vec![0u8; self.secret];
        let ret = unsafe { EVP_PKEY_derive(ctx, secret.as_mut_ptr(), &mut self.secret) };
        unsafe { EVP_PKEY_free(pub_key); }
        unsafe { EVP_PKEY_CTX_free(ctx); }
        if ret != 1 { return Err(RlsError::DeriveError); }
        Ok(secret)
    }
}

impl Drop for EvpCurve {
    fn drop(&mut self) {
        unsafe { EVP_PKEY_free(self.evp_key) }
        self.pub_key.clear();
        self.pub_key.shrink_to_fit();
    }
}

unsafe impl Send for EvpCurve {}

unsafe impl Sync for EvpCurve {}


#[cfg(test)]
mod tests {
    use crate::boring::evp_curve::EvpCurve;

    #[test]
    fn test_evp_curve() {
        let mut x25519 = EvpCurve::new_x25519().unwrap();
        let pub_key = x25519.pub_key();
        println!("{} {:?}", pub_key.len(), pub_key);
        let secret = x25519.diffie_hellman([206, 118, 3, 226, 136, 204, 138, 40, 0, 126, 104, 169, 167, 100, 179, 140, 247, 174, 108, 211, 16, 18, 195, 23, 240, 147, 55, 173, 102, 11, 202, 9]).unwrap();
        println!("{} {:?}", secret.len(), secret);
    }
}