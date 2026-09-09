use crate::boring::{BoringResExt, EvpError};
use crate::buffer::Buf;
use std::os::raw::c_int;

unsafe extern "C" {
    fn X25519_keypair(pub_key: *mut u8, pri_key: *mut u8);
    fn X25519(share_key: *mut u8, pri_key: *const u8, peer_pub_key: *const u8) -> c_int;
}

#[derive(Debug)]
pub struct X25519 {
    pub(crate) pub_key: Option<[u8; 32]>,
    pub(crate) pri_key: [u8; 32],
}

impl X25519 {
    pub fn new_pubkey(pub_key: &mut [u8]) -> X25519 {
        let mut pri_key = [0u8; 32];
        unsafe { X25519_keypair(pub_key.as_mut_ptr(), pri_key.as_mut_ptr()) };
        X25519 {
            pub_key: None,
            pri_key,
        }
    }

    pub fn new() -> X25519 {
        let mut pri_key = [0u8; 32];
        let mut pub_key = [0u8; 32];
        unsafe { X25519_keypair(pub_key.as_mut_ptr(), pri_key.as_mut_ptr()) };
        X25519 {
            pub_key: Some(pub_key),
            pri_key,
        }
    }

    pub fn diffie_hellman_extract(&mut self, pubkey: impl AsRef<[u8]>, out: &mut [u8]) -> Result<(), EvpError> {
        unsafe { X25519(out.as_mut_ptr(), self.pri_key.as_ptr(), pubkey.as_ref().as_ptr()) }
            .ok(EvpError::Derive)
    }

    pub fn diffie_hellman(&mut self, pub_key: impl AsRef<[u8]>) -> Result<Vec<u8>,EvpError> {
        let mut secret = vec![0u8; 32];
        self.diffie_hellman_extract(pub_key, &mut secret)?;
        Ok(secret)
    }

    pub fn pub_key(&self) -> Option<Buf<'_>> {
        Some(Buf::Ref(self.pub_key.as_ref()?))
    }
}