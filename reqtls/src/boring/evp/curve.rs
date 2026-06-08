use super::{PKey, PKeyCtx};
use crate::boring::bindings::*;
use crate::boring::evp::pkey_ctx::PKeyError;
use crate::buffer::Buf;

pub struct EvpCurve {
    evp_key: PKey,
    pub_key_len: usize,
    nid: i32,
    secret: usize,
}


impl EvpCurve {
    pub fn new_x25519() -> Result<EvpCurve, PKeyError> {
        EvpCurve::new(EVP_PKEY_X25519, 32, 32)
    }

    fn new(nid: i32, pub_len: usize, secret_len: usize) -> Result<EvpCurve, PKeyError> {
        Ok(EvpCurve {
            evp_key: PKeyCtx::new_nid(nid)?.generate_key()?,
            pub_key_len: pub_len,
            secret: secret_len,
            nid,
        })
    }

    pub fn pub_key(&self) -> Result<Buf<'_>, PKeyError> {
        let mut pub_key = vec![0; self.pub_key_len];
        self.pub_key_out(&mut pub_key)?;
        Ok(Buf::Vec(pub_key))
    }

    pub fn pub_key_out(&self, out: &mut [u8]) -> Result<(), PKeyError> {
        self.evp_key.extract_pub_key(out)
    }

    pub fn diffie_hellman_extract(&mut self, pubkey: impl AsRef<[u8]>, out: &mut [u8]) -> Result<(), PKeyError> {
        self.evp_key.diffie_hellman(self.nid, pubkey, out)
    }

    pub fn diffie_hellman(&mut self, pub_key: impl AsRef<[u8]>) -> Result<Vec<u8>, PKeyError> {
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
        let mut x25519_1 = EvpCurve::new_x25519().unwrap();
        let pub_key1 = x25519_1.pub_key().unwrap();
        assert_eq!(pub_key1.len(), 32);

        let mut x25519_2 = EvpCurve::new_x25519().unwrap();
        let pub_key2 = x25519_2.pub_key().unwrap();
        assert_eq!(pub_key2.len(), 32);
        let s1 = x25519_1.diffie_hellman(x25519_2.pub_key().unwrap().as_ref()).unwrap();
        let s2 = x25519_2.diffie_hellman(x25519_1.pub_key().unwrap().as_ref()).unwrap();
        assert_eq!(s1, s2);
    }
}