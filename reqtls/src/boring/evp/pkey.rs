use crate::boring::evp::pkey_ctx::PKeyError;
use crate::boring::BoringResExt;
use crate::ffi;
use crate::ffi::CPointer;
use std::ops::{Deref, DerefMut};
use std::os::raw::c_int;

#[repr(C)]
#[allow(clippy::upper_case_acronyms)]
pub struct PKEY {
    _unused: [u8; 0],
}
ffi::c_pointer_free!(PKEY, PKEY_free);

unsafe extern "C" {
    fn PKEY_free(key: *mut PKEY);
    fn PKEY_get_public_key(key: *const PKEY, out: *mut u8, out_len: *mut usize) -> c_int;
    fn PKEY_get_private_key(key: *const PKEY, out: *mut u8, out_len: *mut usize) -> c_int;
    fn PKEY_from_publib_key(nid: c_int, pub_key: *const u8, pub_key_len: usize) -> *mut PKEY;
    fn PKEY_from_private_key(nid: c_int, pri_key: *const u8, pri_key_len: usize) -> *mut PKEY;
    fn PKEY_diffie_hellman(
        nid: c_int,
        local: *const PKEY,
        peer_pub: *const u8,
        peer_pub_len: usize,
        out: *mut u8,
        out_len: *mut usize,
    ) -> c_int;
}

pub struct PKey(CPointer<PKEY>);

impl PKey {
    pub fn new(key: CPointer<PKEY>) -> PKey {
        PKey(key)
    }

    pub fn from_pub_key(nid: i32, pub_key: impl AsRef<[u8]>) -> Result<PKey, PKeyError> {
        let pub_key = pub_key.as_ref();
        let key = unsafe { PKEY_from_private_key(nid, pub_key.as_ptr(), pub_key.len()) };
        let key = CPointer::new_checked(key, PKeyError::InvalidPubKey)?;
        Ok(PKey::new(key))
    }

    pub fn from_pri_key(nid: i32, pri_key: impl AsRef<[u8]>) -> Result<PKey, PKeyError> {
        let pri_key = pri_key.as_ref();
        let key = unsafe { PKEY_from_private_key(nid, pri_key.as_ptr(), pri_key.len()) };
        let key = CPointer::new_checked(key, PKeyError::InvalidPriKey)?;
        Ok(PKey::new(key))
    }

    pub fn extract_pub_key(&self, pub_key: &mut [u8]) -> Result<(), PKeyError> {
        let mut len = pub_key.len();
        unsafe { PKEY_get_public_key(self.as_ptr(), pub_key.as_mut_ptr(), &mut len) }.ok(PKeyError::GetRawPubKeyError)?;
        if len != pub_key.len() { return Err(PKeyError::GetRawPubKeyError); }
        Ok(())
    }

    pub fn extract_pri_key(&self, pri_key: &mut [u8]) -> Result<usize, PKeyError> {
        let mut len = pri_key.len();
        unsafe { PKEY_get_private_key(self.as_ptr(), pri_key.as_mut_ptr(), &mut len).ok(PKeyError::GetRawPriKeyError) }?;
        Ok(len)
    }

    pub fn diffie_hellman(&self, nid: i32, peer_pub: impl AsRef<[u8]>, out: &mut [u8]) -> Result<(), PKeyError> {
        let peer_pub = peer_pub.as_ref();
        let mut len = out.len();
        let ret = unsafe { PKEY_diffie_hellman(nid, self.as_ptr(), peer_pub.as_ptr(), peer_pub.len(), out.as_mut_ptr(), &mut len) };
        if len != out.len() { return Err(PKeyError::DiffieHellmanError); }
        ret.ok(PKeyError::DiffieHellmanError)
    }
}

impl Deref for PKey {
    type Target = CPointer<PKEY>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for PKey {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(test)]
mod pkey_tests {
    use crate::boring::bindings::EVP_PKEY_X25519;
    use crate::boring::evp::pkey::PKey;

    #[test]
    fn pkey_test() {
        let x25519_pri = [39, 215, 30, 253, 43, 229, 105, 81, 50, 116, 29, 216, 128, 50, 8, 85, 134, 61, 254, 56, 164, 187, 30, 208, 94, 35, 68, 188, 161, 194, 236, 172];
        let pkey = PKey::from_pri_key(EVP_PKEY_X25519, x25519_pri).unwrap();
        let mut secret = [0; 32];
        let x25519_pub = [206, 118, 3, 226, 136, 204, 138, 40, 0, 126, 104, 169, 167, 100, 179, 140, 247, 174, 108, 211, 16, 18, 195, 23, 240, 147, 55, 173, 102, 11, 202, 9];
        pkey.diffie_hellman(EVP_PKEY_X25519, x25519_pub, &mut secret).unwrap();
        assert_eq!(secret, [238, 111, 11, 232, 208, 255, 35, 61, 182, 149, 161, 95, 69, 224, 252, 167, 95, 103, 31, 235, 233, 213, 155, 103, 19, 44, 241, 117, 145, 201, 141, 55]);
    }
}

















