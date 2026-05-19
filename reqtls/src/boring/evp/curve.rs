use crate::boring::bindings::*;
use crate::boring::evp::EvpError;
use crate::boring::BoringResExt;
use crate::buffer::Buf;
use crate::ffi::CPointer;
use std::ptr::null_mut;

pub struct EvpCurve {
    evp_key: CPointer<EVP_PKEY>,
    pub_key_len: usize,
    nid: i32,
    secret: usize,
}


impl EvpCurve {
    pub fn new_x25519() -> Result<EvpCurve, EvpError> {
        EvpCurve::new(EVP_PKEY_X25519, 32, 32)
    }

    fn new(nid: i32, pub_len: usize, secret_len: usize) -> Result<EvpCurve, EvpError> {
        let ctx = CPointer::new_checked(unsafe { EVP_PKEY_CTX_new_id(nid, null_mut()) }, EvpError::InitEvpPKeyCtxError)?;
        unsafe { EVP_PKEY_keygen_init(ctx.as_mut_ptr()) }.ok(EvpError::InitKeygenError)?;
        let mut pkey = CPointer::nullptr();
        unsafe { EVP_PKEY_keygen(ctx.as_mut_ptr(), pkey.as_mut()) }.ok(EvpError::KeyGenError)?;
        Ok(EvpCurve {
            evp_key: pkey,
            pub_key_len: pub_len,
            secret: secret_len,
            nid,
        })
    }

    pub fn pub_key(&self) -> Result<Buf<'_>, EvpError> {
        let mut pub_key = vec![0; self.pub_key_len];
        self.pub_key_out(&mut pub_key)?;
        Ok(Buf::Vec(pub_key))
    }

    pub fn pub_key_out(&self, out: &mut [u8]) -> Result<(), EvpError> {
        let mut len = out.len();
        let ret = unsafe { EVP_PKEY_get_raw_public_key(self.evp_key.as_ptr(), out.as_mut_ptr(), &mut len) };
        if len != out.len() { return Err(EvpError::GetPubKeyError); }
        ret.ok(EvpError::GetPubKeyError)
    }

    pub fn diffie_hellman_extract(&mut self, pubkey: impl AsRef<[u8]>, out: &mut [u8]) -> Result<(), EvpError> {
        let pub_key = CPointer::new_checked(unsafe {
            EVP_PKEY_new_raw_public_key(
                self.nid,
                null_mut(),
                pubkey.as_ref().as_ptr(),
                pubkey.as_ref().len(),
            )
        }, EvpError::NewPublicKeyError)?;
        let ctx = CPointer::new_checked(unsafe { EVP_PKEY_CTX_new(self.evp_key.as_mut_ptr(), null_mut()) }, EvpError::InitEvpPKeyCtxError)?;
        unsafe { EVP_PKEY_derive_init(ctx.as_mut_ptr()) }.ok(EvpError::InitDeriveError)?;
        unsafe { EVP_PKEY_derive_set_peer(ctx.as_mut_ptr(), pub_key.as_mut_ptr()) }.ok(EvpError::SetPeerDeriveError)?;
        unsafe { EVP_PKEY_derive(ctx.as_mut_ptr(), out.as_mut_ptr(), &mut self.secret) }.ok(EvpError::DeriveError)?;
        Ok(())
    }

    pub fn diffie_hellman(&mut self, pub_key: impl AsRef<[u8]>) -> Result<Vec<u8>, EvpError> {
        let mut secret = vec![0u8; self.secret];
        self.diffie_hellman_extract(pub_key, &mut secret)?;
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
        println!("{} {:?}", pub_key.len(), pub_key.as_ref());
        let secret = x25519.diffie_hellman([206, 118, 3, 226, 136, 204, 138, 40, 0, 126, 104, 169, 167, 100, 179, 140, 247, 174, 108, 211, 16, 18, 195, 23, 240, 147, 55, 173, 102, 11, 202, 9]).unwrap();
        println!("{} {:?}", secret.len(), secret);
    }
}