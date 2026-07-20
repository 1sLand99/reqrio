use crate::hash::HashError;
use crate::{HashType, Hmac};
use std::borrow::Cow;

#[allow(dead_code)]
pub struct Hkdf<'a> {
    hash: HashType,
    prk: Cow<'a, [u8]>,
}


impl<'a> Hkdf<'a> {
    pub fn new(salt: &[u8], ikm: &[u8], hash: HashType) -> Result<Hkdf<'a>, HashError> {
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

    pub fn extract(hash: HashType, salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>, HashError> {
        let mut out = vec![0; hash.hash_size()];
        let mut hmac = Hmac::new(salt, hash)?;
        hmac.update(ikm)?;
        hmac.finalize_extract(&mut out)?;
        Ok(out)
    }

    pub fn extend_multi(&mut self, infos: &[&[u8]], out: &mut [u8]) -> Result<(), HashError> {
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
    pub fn extend(&mut self, infos: &[u8], out: &mut [u8]) -> Result<(), HashError> {
        self.extend_multi(&[infos], out)
    }

    pub fn hkdf(&mut self, label: &str, content: &[u8], out: &mut [u8]) -> Result<(), HashError> {
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
    use crate::boring::bindings::EVP_AEAD_DEFAULT_TAG_LENGTH;
    use crate::boring::AeadCtx;
    use crate::extend::Aead;
    use crate::hkdf::Hkdf;
    use crate::key::{DerivedKey, Key};
    use crate::{Cipher, CipherSuite, HashType, Version};

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
        let mut derived = DerivedKey::new([0; 32], [0; 32], Default::default(), None);
        derived.init(&CipherSuite::TLS_AES_256_GCM_SHA384);
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

    #[test]
    fn test_quic() {
        let cid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let init_salt = [0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a];
        println!("{:?}", init_salt);
        let mut hkdf = Hkdf::new(&init_salt, &cid, HashType::Sha256).unwrap();
        assert_eq!(hex::encode(hkdf.prk.as_ref()), "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44");

        let mut server_initial_secret = [0; 32];
        hkdf.hkdf("tls13 server in", &[], &mut server_initial_secret).unwrap();
        assert_eq!(hex::encode(server_initial_secret), "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b");


        let mut client_initial_secret = [0; 32];
        hkdf.hkdf("tls13 client in", b"", &mut client_initial_secret).unwrap();
        assert_eq!(hex::encode(client_initial_secret), "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea");

        let mut hkdf = Hkdf::from_prk(&client_initial_secret, HashType::Sha256);
        let mut key = [0; 16];
        hkdf.hkdf("tls13 quic key", b"", &mut key).unwrap();
        assert_eq!(hex::encode(key), "1f369613dd76d5467730efcbe3b1a22d");

        let mut iv = [0; 12];
        hkdf.hkdf("tls13 quic iv", b"", &mut iv).unwrap();
        assert_eq!(hex::encode(iv), "fa044b2f42a3fd3b46fb255c");

        let mut hp_key = [0; 16];
        hkdf.hkdf("tls13 quic hp", b"", &mut hp_key).unwrap();
        assert_eq!(hex::encode(hp_key), "9f50449e04a0e810283a1e9933adedd2");

        let sample = hex::decode("d1b1c98dd7689fb8ec11d242b123dc9b").unwrap();
        let cipher = Cipher::aes_128_ecb().with_secret_key(&hp_key, None);
        let mask = cipher.encrypt(sample).unwrap()[..5].to_owned();
        assert_eq!(hex::encode(&mask), "437b9aec36");

        let mut hdr = hex::decode("c300000001088394c8f03e5157080000449e00000002").unwrap();
        hdr[0] ^= mask[0] & 0x0f;
        hdr[18..22].iter_mut().enumerate().for_each(|(i, v)| *v ^= mask[i + 1]);
        assert_eq!(hex::encode(hdr), "c000000001088394c8f03e5157080000449e7b9aec34");


        let pd = "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578616d706c652e636f6dff01000100000a00080006001d0017001800100007000504616c706e000500050100000000003300260024001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b0003020304000d0010000e0403050306030203080408050806002d00020101001c00024001003900320408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e51570806048000ffff";
        let mut pd = hex::decode(pd).unwrap();
        pd.resize(1162, 0);
        println!("{:?}", pd);

        let aead = AeadCtx::new(&Aead::AES_128_GCM, &key, EVP_AEAD_DEFAULT_TAG_LENGTH).unwrap();
        let mut out = [0; 4096];
        let aad = hex::decode("c300000001088394c8f03e5157080000449e00000002").unwrap();
        let sbs = 2u64.to_be_bytes();
        for (i, b) in iv[4..12].iter_mut().enumerate() {
            *b ^= sbs[i];
        }
        let len = aead.seal2(&mut out, &iv, &pd, &aad).unwrap();
        println!("{:?}", hex::encode(&out[..len]));

        let mut hkdf = Hkdf::from_prk(&server_initial_secret, HashType::Sha256);
        hkdf.hkdf("tls13 quic key", b"", &mut key).unwrap();
        assert_eq!(hex::encode(key), "cf3a5331653c364c88f0f379b6067e37");

        hkdf.hkdf("tls13 quic iv", b"", &mut iv).unwrap();
        assert_eq!(hex::encode(iv), "0ac1493ca1905853b0bba03e");

        hkdf.hkdf("tls13 quic hp", b"", &mut hp_key).unwrap();
        assert_eq!(hex::encode(hp_key), "c206b8d9b9f0f37644430b490eeaa314")
    }
}