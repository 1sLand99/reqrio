use crate::boring::bindings::*;
use crate::boring::evp::EvpError;
use crate::boring::{BoringResExt, EcCurve, EcError, EvpCurve};
use std::mem::MaybeUninit;
use std::ptr::null_mut;
use crate::hash::HashError;
use crate::NamedCurve;

#[derive(Debug)]
pub enum MLKEMError {
    InvalidPubKeyLen(usize),
    NewPrivateKeyError,
    DecapError,
    Evp(EvpError),
    Ec(EcError),
    Hmac(HashError),
    UnSupported(NamedCurve),
}

impl From<EvpError> for MLKEMError {
    fn from(e: EvpError) -> Self {
        MLKEMError::Evp(e)
    }
}

impl From<EcError> for MLKEMError {
    fn from(e: EcError) -> Self {
        MLKEMError::Ec(e)
    }
}

impl From<HashError> for MLKEMError {
    fn from(e: HashError) -> Self {
        MLKEMError::Hmac(e)
    }
}

pub struct MLKEM768 {
    private_key: MaybeUninit<MLKEM768_private_key>,
}

impl MLKEM768 {
    const MLKEM768_PUBLIC_KEY_BYTES: usize = 1184;
    const MLKEM768_CIPHERTEXT_BYTES: usize = 1088;

    pub fn new_pubkey(pub_key: &mut [u8]) -> Result<MLKEM768, MLKEMError> {
        if pub_key.len() != MLKEM768::MLKEM768_PUBLIC_KEY_BYTES { return Err(MLKEMError::InvalidPubKeyLen(pub_key.len())); }
        let mut private_key = MaybeUninit::uninit();
        unsafe {
            MLKEM768_generate_key(
                pub_key.as_mut_ptr(),
                null_mut(),
                private_key.as_mut_ptr())
        };
        Ok(MLKEM768 {
            private_key,
        })
    }

    pub fn decap(&self, key: &[u8]) -> Result<[u8; 32], MLKEMError> {
        let mut out = [0; 32];
        self.decap_extract(key, &mut out)?;
        Ok(out)
    }

    pub fn decap_extract(&self, key: &[u8], out: &mut [u8]) -> Result<(), MLKEMError> {
        unsafe {
            MLKEM768_decap(
                out.as_mut_ptr(),
                key.as_ptr(),
                key.len(),
                self.private_key.as_ptr(),
            )
        }.ok(MLKEMError::DecapError)
    }

    pub fn encap(&self, key: &[u8]) -> ([u8; MLKEM768::MLKEM768_CIPHERTEXT_BYTES], [u8; 32]) {
        let mut ciphertext = [0; MLKEM768::MLKEM768_CIPHERTEXT_BYTES];
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


pub enum Hybrid {
    X25519MLKEM768 {
        kem768: MLKEM768,
        evp_curve: EvpCurve,
        pubkey: [u8; 32 + MLKEM768::MLKEM768_PUBLIC_KEY_BYTES],
    },
    SecP256r1MLKEM768 {
        kem768: MLKEM768,
        ec_curve: EcCurve,
        pubkey: [u8; 65 + MLKEM768::MLKEM768_PUBLIC_KEY_BYTES],
    },
}

impl Hybrid {
    pub fn new_x25519_768() -> Result<Hybrid, MLKEMError> {
        let mut pubkey = [0; 32 + MLKEM768::MLKEM768_PUBLIC_KEY_BYTES];
        let evp_curve = EvpCurve::new_x25519()?;
        evp_curve.pub_key_out(&mut pubkey[1184..1216])?;
        Ok(Hybrid::X25519MLKEM768 {
            kem768: MLKEM768::new_pubkey(&mut pubkey[0..1184])?,
            evp_curve,
            pubkey,
        })
    }

    pub fn new_p256r1_768() -> Result<Hybrid, MLKEMError> {
        let mut pubkey = [0; 65 + MLKEM768::MLKEM768_PUBLIC_KEY_BYTES];
        let ec_curve = EcCurve::new_p256()?;
        pubkey[0..65].copy_from_slice(ec_curve.pub_key()?.as_slice());
        Ok(Hybrid::SecP256r1MLKEM768 {
            kem768: MLKEM768::new_pubkey(&mut pubkey[65..1249])?,
            ec_curve,
            pubkey,
        })
    }


    pub fn diffie_hellman(&mut self, _server: bool, key: &[u8]) -> Result<Vec<u8>, MLKEMError> {
        match self {
            Hybrid::X25519MLKEM768 { kem768, evp_curve, .. } => {
                let mut share_secret = vec![0; 64];
                kem768.decap_extract(&key[0..1088], &mut share_secret[0..32])?;
                evp_curve.diffie_hellman_extract(&key[1088..1120], &mut share_secret[32..64])?;
                Ok(share_secret)
            }
            Hybrid::SecP256r1MLKEM768 { kem768, ec_curve, .. } => {
                let mut share_secret = vec![0; 64];
                ec_curve.diffie_hellman_extract(&key[0..65], &mut share_secret[0..32])?;
                kem768.decap_extract(&key[65..1153], &mut share_secret[32..64])?;
                Ok(share_secret)
            }
        }
    }

    pub fn pubkey(&self) -> &[u8] {
        match self {
            Hybrid::X25519MLKEM768 { pubkey, .. } => pubkey,
            Hybrid::SecP256r1MLKEM768 { pubkey, .. } => pubkey,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::boring::ml_kem::MLKEM768;

    #[test]
    fn test_ml_kem() {
        let mut pub_key = [0; MLKEM768::MLKEM768_PUBLIC_KEY_BYTES];
        let ml_kem = MLKEM768::new_pubkey(&mut pub_key).unwrap();
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