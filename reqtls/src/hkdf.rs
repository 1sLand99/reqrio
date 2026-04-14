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
    use crate::derived::DerivedKey;
    use crate::hkdf::Hkdf;
    use crate::{HashType, Hasher, Version};
    use std::fs;
    use crate::extend::Aead;

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
        let client_hello = fs::read("/home/xl/下载/rustls-main/ClientHello").unwrap();
        let server_hello = fs::read("/home/xl/下载/rustls-main/ServerHello").unwrap();
        let mut hasher = Hasher::new(HashType::Sha384).unwrap();
        hasher.update(&client_hello).unwrap();
        hasher.update(&server_hello).unwrap();
        let hash = hasher.finalize().unwrap();
        println!("session_hash: {:?}", hash);

        let mut derived = DerivedKey::new([0; 32], [0; 32]);
        derived.init(&Aead::AES_256_GCM, &Hasher::new(HashType::Sha384).unwrap(), &Version::TLS_1_3);
        let share_secret = fs::read("/home/xl/下载/rustls-main/ShareSecret").unwrap();
        println!("share_secret: {:?}", share_secret);
        derived.make_handshake_traffic_secret(share_secret.clone(), &hash).unwrap();
        let key = derived.make_tls13_cipher_key(true).unwrap();
        println!("{:?}", key.get_side(&Version::TLS_1_3, false));
        println!("========================>finish<============================");

        let encrypted_extension = fs::read("/home/xl/下载/rustls-main/EncryptedExtensions").unwrap();
        let certificate = fs::read("/home/xl/下载/rustls-main/Certificate").unwrap();
        let certificate_verify = fs::read("/home/xl/下载/rustls-main/CertificateVerify").unwrap();
        let mut hasher = Hasher::new(HashType::Sha384).unwrap();
        hasher.update(&client_hello).unwrap();
        hasher.update(&server_hello).unwrap();
        hasher.update(&encrypted_extension).unwrap();
        hasher.update(&certificate).unwrap();
        hasher.update(&certificate_verify).unwrap();
        let hash = hasher.finalize().unwrap();
        println!("session_hash: {:?}", hash);
        let server_verify = derived.make_tls13_finish(true, &hash).unwrap();
        let mut hasher = Hasher::new(HashType::Sha384).unwrap();
        hasher.update(&client_hello).unwrap();
        hasher.update(&server_hello).unwrap();
        hasher.update(&encrypted_extension).unwrap();
        hasher.update(&certificate).unwrap();
        hasher.update(&certificate_verify).unwrap();
        hasher.update([20, 0, 0, 48]).unwrap();
        hasher.update(&server_verify).unwrap();
        let hash = hasher.finalize().unwrap();
        println!("session_hash: {:?}", hash);
        let client_verify = derived.make_tls13_finish(false, &hash).unwrap();
        println!("client_verify: {:?}", client_verify);
        derived.make_application_traffic_secret(&hash).unwrap();
        let key = derived.make_cipher_key(&Version::TLS_1_3, false).unwrap();
        println!("key: {:#?}", key);
    }
}