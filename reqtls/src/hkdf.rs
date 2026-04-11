use crate::error::RlsResult;
use crate::{HashType, Hmac};

#[allow(dead_code)]
pub struct Hkdf {
    hash: HashType,
    prk: Vec<u8>,
}


impl Hkdf {
    pub fn new(salt: &[u8], ikm: &[u8], hash: HashType) -> RlsResult<Hkdf> {
        let prk = match salt.is_empty() {
            true => Hkdf::extract(hash, &vec![0; hash.hash_size()], ikm)?,
            false => Hkdf::extract(hash, salt, ikm)?
        };
        Ok(Hkdf::from_prk(prk, hash))
    }

    pub fn from_prk(prk: Vec<u8>, hash: HashType) -> Hkdf {
        Hkdf {
            hash,
            prk,
        }
    }

    pub fn extract(hash: HashType, salt: &[u8], ikm: &[u8]) -> RlsResult<Vec<u8>> {
        let mut out = vec![0; hash.hash_size()];
        let mut hmac = Hmac::new(salt, hash)?;
        hmac.update(ikm)?;
        hmac.finalize_extract(&mut out)?;
        Ok(out)
    }

    pub fn extend_multi(&mut self, infos: &[&[u8]], out: &mut [u8]) -> RlsResult<()> {
        let mut prev = vec![0; self.hash.hash_size()];
        for (i, chunk) in out.chunks_mut(self.hash.hash_size()).enumerate() {
            let mut hmac = Hmac::new(&self.prk, self.hash)?;
            if i != 0 { hmac.update(&prev)?; }
            for info in infos {
                hmac.update(info)?;
            }
            hmac.update([i as u8 + 1])?;
            hmac.finalize_extract(&mut prev)?;
            chunk.copy_from_slice(&prev.as_slice()[..chunk.len()]);
        }
        Ok(())
    }

    pub fn extend(&mut self, infos: &[u8], out: &mut [u8]) -> RlsResult<()> {
        self.extend_multi(&[infos], out)
    }

    pub fn hkdf(&mut self, label: &str, content: &[u8], out: &mut [u8]) -> RlsResult<()> {
        let len = out.len() as u16;
        self.extend_multi(&[
            //out len u16
            &len.to_be_bytes(),
            //label
            &[label.len() as u8],
            label.as_bytes(),
            //content
            &[content.len() as u8],
            content
        ], out)
    }
}

#[cfg(test)]
mod tests {
    use crate::hkdf::Hkdf;
    use crate::HashType;

    #[test]
    fn test_hkdf() {
        let mut hkdf = Hkdf::new(b"test", b"test", HashType::Sha256).unwrap();
        let mut out = vec![0; 100];
        let info = (0..100).collect::<Vec<u8>>();
        hkdf.extend(&info, &mut out).unwrap();
        assert_eq!(&out[..6], &[76, 35, 136, 208, 215, 198]);

        let secret = (0..32).collect::<Vec<u8>>();
        let mut hkdf = Hkdf::from_prk(secret, HashType::Sha256);
        hkdf.hkdf("tls13 derived", &info, &mut out).unwrap();
        assert_eq!(&out[..6], &[35, 255, 131, 135, 179, 156]);
    }
}