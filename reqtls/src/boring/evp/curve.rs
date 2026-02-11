use crate::boring::BoringResExt;
use crate::error::RlsResult;
use crate::RlsError;
use std::ptr::null_mut;
use crate::boring::bindings::*;
use crate::ffi::CPointer;

pub struct EvpCurve {
    evp_key: CPointer<EVP_PKEY>,
    pub_key_len: usize,
    nid: i32,
    secret: usize,
}


impl EvpCurve {
    pub fn new_x25519() -> RlsResult<EvpCurve> {
        EvpCurve::new(EVP_PKEY_X25519, 32, 32)
    }

    fn new(nid: i32, pub_len: usize, secret_len: usize) -> RlsResult<EvpCurve> {
        let ctx = CPointer::new_checked(unsafe { EVP_PKEY_CTX_new_id(nid, null_mut()) }, RlsError::InitEvpPKeyCtxError)?;
        unsafe { EVP_PKEY_keygen_init(ctx.as_mut_ptr()) }.ok(RlsError::InitKeygenError)?;
        let mut pkey = CPointer::nullptr();
        unsafe { EVP_PKEY_keygen(ctx.as_mut_ptr(), pkey.as_mut()) }.ok(RlsError::KeyGenError)?;
        Ok(EvpCurve {
            evp_key: pkey,
            pub_key_len: pub_len,
            secret: secret_len,
            nid,
        })
    }

    pub fn pub_key(&mut self) -> RlsResult<Vec<u8>> {
        let mut pub_key = vec![0; self.pub_key_len];
        let ret = unsafe { EVP_PKEY_get_raw_public_key(self.evp_key.as_ptr(), pub_key.as_mut_ptr(), &mut self.pub_key_len) };
        if ret != 1 { return Err(RlsError::GetPubKeyError); }
        Ok(pub_key)
    }

    pub fn diffie_hellman(&mut self, pub_key: impl AsRef<[u8]>) -> RlsResult<Vec<u8>> {
        let pub_key = CPointer::new_checked(unsafe {
            EVP_PKEY_new_raw_public_key(
                self.nid,
                null_mut(),
                pub_key.as_ref().as_ptr(),
                pub_key.as_ref().len(),
            )
        }, RlsError::NewPublicKeyError)?;
        let ctx = CPointer::new_checked(unsafe { EVP_PKEY_CTX_new(self.evp_key.as_mut_ptr(), null_mut()) }, RlsError::InitEvpPKeyCtxError)?;
        unsafe { EVP_PKEY_derive_init(ctx.as_mut_ptr()) }.ok(RlsError::InitDeriveError)?;
        unsafe { EVP_PKEY_derive_set_peer(ctx.as_mut_ptr(), pub_key.as_mut_ptr()) }.ok(RlsError::SetPeerDeriveError)?;
        let mut secret = vec![0u8; self.secret];
        unsafe { EVP_PKEY_derive(ctx.as_mut_ptr(), secret.as_mut_ptr(), &mut self.secret) }.ok(RlsError::DeriveError)?;
        Ok(secret)
    }
}


#[cfg(test)]
mod tests {
    use crate::boring::evp::curve::EvpCurve;

    #[test]
    fn test_evp_curve() {
        let mut x25519 = EvpCurve::new_x25519().unwrap();
        let pub_key = x25519.pub_key().unwrap();
        println!("{} {:?}", pub_key.len(), pub_key);
        let secret = x25519.diffie_hellman([206, 118, 3, 226, 136, 204, 138, 40, 0, 126, 104, 169, 167, 100, 179, 140, 247, 174, 108, 211, 16, 18, 195, 23, 240, 147, 55, 173, 102, 11, 202, 9]).unwrap();
        println!("{} {:?}", secret.len(), secret);
    }
}