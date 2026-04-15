use crate::error::RlsResult;
use crate::{HashType, Hmac};
use std::borrow::Cow;

#[allow(dead_code)]
pub struct Hkdf<'a> {
    hash: HashType,
    prk: Cow<'a, [u8]>,
}


impl<'a> Hkdf<'a> {
    pub fn new(salt: &[u8], ikm: &[u8], hash: HashType) -> RlsResult<Hkdf<'a>> {
        let prk = match salt.is_empty() {
            true => Hkdf::extract(hash, &vec![0; hash.hash_size()], ikm)?,
            false => Hkdf::extract(hash, salt, ikm)?
        };
        Ok(Hkdf::from_prk(prk, hash))
    }

    pub fn from_prk(prk: impl Into<Cow<'a, [u8]>>, hash: HashType) -> Hkdf<'a> {
        Hkdf {
            hash,
            prk: prk.into(),
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

    #[allow(dead_code)]
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

    pub fn into_prk(self) -> Cow<'a, [u8]> { self.prk }
}

#[cfg(test)]
mod tests {
    use crate::derived::{DerivedKey, Key};
    use crate::extend::Aead;
    use crate::hkdf::Hkdf;
    use crate::{HashType, Hasher, Version};

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

    #[test]
    fn test_hkdf_local() {
        let hash = [160, 123, 172, 137, 109, 33, 28, 150, 18, 251, 24, 221, 150, 16, 121, 34, 68, 216, 55, 115, 134, 77, 226, 34, 247, 222, 165, 187, 194, 37, 246, 171, 37, 243, 23, 41, 163, 49, 0, 0, 137, 112, 219, 4, 9, 220, 174, 156];
        let mut derived = DerivedKey::new([0; 32], [0; 32]);
        derived.init(&Aead::AES_256_GCM, &Hasher::new(HashType::Sha384).unwrap(), &Version::TLS_1_3);
        let share_secret = [20, 12, 97, 149, 53, 54, 162, 204, 253, 108, 221, 23, 41, 241, 68, 218, 246, 201, 45, 203, 235, 232, 39, 139, 164, 162, 176, 211, 65, 52, 36, 65];
        derived.make_handshake_traffic_secret(share_secret.to_vec(), &hash).unwrap();
        let key = derived.make_tls13_cipher_key().unwrap();
        assert_eq!(key.client_key(), [231, 94, 131, 14, 3, 98, 169, 54, 43, 91, 8, 96, 211, 105, 173, 66, 64, 67, 215, 242, 220, 165, 135, 181, 67, 224, 56, 154, 103, 98, 105, 104]);
        assert_eq!(key.server_key(), [155, 167, 166, 135, 254, 26, 173, 62, 73, 205, 135, 67, 124, 190, 11, 192, 77, 200, 161, 19, 129, 32, 162, 89, 30, 74, 182, 130, 219, 115, 227, 184]);
        assert_eq!(key.client_iv(), [249, 151, 71, 46, 34, 36, 83, 210, 78, 215, 185, 233]);
        assert_eq!(key.server_iv(), [242, 48, 254, 72, 191, 65, 51, 249, 51, 219, 135, 82]);
        let hash = [107, 219, 183, 87, 169, 165, 132, 92, 24, 248, 124, 133, 40, 133, 100, 249, 64, 241, 10, 69, 215, 120, 124, 251, 103, 39, 155, 145, 31, 206, 207, 100, 190, 241, 61, 104, 72, 91, 209, 201, 171, 138, 14, 4, 211, 82, 211, 212];
        let server_verify = derived.make_finish(Version::TLS_1_3, true, &hash).unwrap();
        assert_eq!(server_verify, [20, 0, 0, 48, 106, 93, 47, 37, 24, 248, 49, 166, 135, 159, 17, 43, 155, 90, 165, 141, 34, 167, 10, 149, 65, 151, 64, 170, 130, 198, 242, 41, 220, 42, 152, 8, 212, 242, 35, 70, 25, 25, 124, 214, 218, 170, 201, 248, 252, 246, 222, 66]);
        let hash = [179, 160, 168, 205, 252, 97, 71, 87, 212, 81, 243, 20, 192, 141, 147, 84, 224, 148, 72, 190, 22, 236, 148, 126, 39, 184, 25, 190, 95, 64, 103, 223, 218, 147, 161, 205, 205, 148, 183, 32, 57, 12, 2, 237, 164, 75, 185, 124];
        let client_verify = derived.make_finish(Version::TLS_1_3, false, &hash).unwrap();
        assert_eq!(client_verify, [20, 0, 0, 48, 74, 39, 58, 51, 253, 181, 153, 112, 250, 56, 1, 226, 174, 0, 89, 150, 152, 153, 252, 9, 169, 16, 115, 105, 23, 59, 16, 177, 95, 107, 231, 25, 187, 239, 39, 23, 121, 230, 207, 76, 254, 197, 180, 171, 11, 53, 66, 54]);
        derived.make_application_traffic_secret(&hash).unwrap();
        let key = derived.make_cipher_key(&Version::TLS_1_3, false).unwrap();
        if let Key::TLS13 {
            send_key,
            send_iv,
            recv_key,
            recv_iv,
        } = key {
            assert_eq!(send_key, [190, 39, 218, 81, 38, 172, 202, 89, 15, 37, 9, 170, 188, 157, 120, 7, 248, 175, 113, 187, 99, 136, 0, 243, 236, 2, 169, 63, 149, 64, 195, 127]);
            assert_eq!(recv_key, [67, 13, 200, 88, 63, 34, 30, 54, 74, 147, 60, 178, 20, 143, 245, 53, 177, 252, 87, 88, 187, 91, 213, 249, 107, 220, 180, 152, 53, 167, 0, 124]);
            assert_eq!(send_iv, [39, 232, 90, 194, 220, 97, 108, 134, 85, 102, 141, 50]);
            assert_eq!(recv_iv, [202, 214, 80, 222, 184, 70, 216, 66, 195, 156, 43, 112])
        }
    }
}