use crate::boring::bindings::*;
use crate::boring::evp::EvpError;
use crate::boring::{BoringResExt, EvpCurve};
use crate::hkdf::Hkdf;
use crate::HashType;
use std::mem::MaybeUninit;
use std::ptr::null_mut;

#[derive(Debug)]
pub enum MlKemError {
    InvalidPubKeyLen(usize),
    NewPrivateKeyError,
    DecapError,
    EvpError(EvpError),
}

impl From<EvpError> for MlKemError {
    fn from(e: EvpError) -> Self {
        MlKemError::EvpError(e)
    }
}

pub struct MlKem768 {
    private_key: MaybeUninit<MLKEM768_private_key>,
}

impl MlKem768 {
    const MLKEM768_PUBLIC_KEY_BYTES: usize = 1184;
    const MLKEM768_CIPHERTEXT_BYTES: usize = 1088;

    pub fn new_pubkey(pub_key: &mut [u8]) -> Result<MlKem768, MlKemError> {
        if pub_key.len() != MlKem768::MLKEM768_PUBLIC_KEY_BYTES { return Err(MlKemError::InvalidPubKeyLen(pub_key.len())); }
        let mut private_key = MaybeUninit::uninit();
        unsafe {
            MLKEM768_generate_key(
                pub_key.as_mut_ptr(),
                null_mut(),
                private_key.as_mut_ptr())
        };
        Ok(MlKem768 {
            private_key,
        })
    }

    pub fn decap(&self, key: &[u8]) -> Result<[u8; 32], MlKemError> {
        let mut out = [0; 32];
        unsafe {
            MLKEM768_decap(
                out.as_mut_ptr(),
                key.as_ptr(),
                key.len(),
                self.private_key.as_ptr(),
            )
        }.ok(MlKemError::DecapError)?;
        Ok(out)
    }

    pub fn encap(&self, key: &[u8]) -> ([u8; MlKem768::MLKEM768_CIPHERTEXT_BYTES], [u8; 32]) {
        let mut ciphertext = [0; MlKem768::MLKEM768_CIPHERTEXT_BYTES];
        let mut kem_ss = [0; 32];
        let mut pub_key = MaybeUninit::uninit();
        let mut cbs = CBS {
            data: key.as_ptr(),
            len: key.len(),
        };
        unsafe { MLKEM768_parse_public_key(pub_key.as_mut_ptr(), &mut cbs) };


        unsafe {
            MLKEM768_encap(
                ciphertext.as_mut_ptr(),
                kem_ss.as_mut_ptr(),
                pub_key.as_ptr(),
            )
        };
        (ciphertext, kem_ss)
    }
}


pub struct X25519MlKem768 {
    kem768: MlKem768,
    x25519: EvpCurve,
    pub_key: [u8; 32 + MlKem768::MLKEM768_PUBLIC_KEY_BYTES],
}

impl X25519MlKem768 {
    pub fn new_client() -> Result<X25519MlKem768, MlKemError> {
        let mut pub_key = [0; 32 + MlKem768::MLKEM768_PUBLIC_KEY_BYTES];
        let x25519 = EvpCurve::new_x25519()?;
        x25519.pub_key_out(&mut pub_key[..32])?;
        let kem768 = MlKem768::new_pubkey(&mut pub_key[32..])?;
        Ok(X25519MlKem768 {
            kem768,
            x25519,
            pub_key,
        })
    }

    pub fn diffie_hellman(&mut self, server: bool, key: &[u8]) -> Result<Vec<u8>, MlKemError> {
        let x25519_secret = self.x25519.diffie_hellman(&key.as_ref()[..32])?;
        let (_, kem) = match server {
            true => self.kem768.encap(&key.as_ref()[32..]),
            false => ([0; MlKem768::MLKEM768_CIPHERTEXT_BYTES], self.kem768.decap(&key.as_ref()[32..])?)
        };
        let hybrid = [x25519_secret.as_slice(), &kem].concat();
        let mut hkdf = Hkdf::new(&[], &hybrid, HashType::Sha256).unwrap();
        let mut out = vec![0; 32];
        hkdf.extend(&[], &mut out).unwrap();
        Ok(out)
    }

    pub fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }
}

#[cfg(test)]
mod tests {
    use crate::boring::ml_kem::MlKem768;

    #[test]
    fn test_ml_kem() {
        let mut pub_key = [0; MlKem768::MLKEM768_PUBLIC_KEY_BYTES];
        let ml_kem = MlKem768::new_pubkey(&mut pub_key).unwrap();
        println!("pub_key： {:?}", pub_key);
        // assert!(!ml_kem.private_key.as_ptr().is_null());
        let (ciphertext, mss) = ml_kem.encap(pub_key.as_ref());
        println!("ciphertext：{:?}", ciphertext);
        println!("mss：{:?}", mss);

        let kss = ml_kem.decap(ciphertext.as_ref()).unwrap();
        println!("kss：{:?}", kss);
        assert_eq!(mss, kss);
    }
}