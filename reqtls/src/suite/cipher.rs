use std::sync::atomic::{AtomicU64, Ordering};
use crate::boring::{CryptDecodeParam, CryptEncodeParam, Crypto};
use crate::buffer::{CipherDecodeBuffer, CipherEncodeBuffer};
use crate::error::RlsResult;
use crate::extend::Aead;
use crate::suite::iv::Iv;
use crate::HashType;

pub struct TlsCipher {
    crypto: Crypto,
    iv: Iv,
    seq: AtomicU64,
}


impl TlsCipher {
    pub fn none() -> TlsCipher {
        TlsCipher {
            crypto: Crypto::None,
            iv: Iv::new(&[], vec![]),
            seq: AtomicU64::new(0),
        }
    }

    pub fn set_key(&mut self, key: &[u8], mac_key: &[u8], aead: &Aead, hash: HashType) -> RlsResult<()> {
        self.crypto = Crypto::from_aead(key, mac_key, aead, hash)?;
        self.seq = AtomicU64::new(0);
        Ok(())
    }

    pub fn set_iv(&mut self, iv: Iv) {
        self.iv = iv;
    }


    pub fn encrypt(&mut self, mut buffer: CipherEncodeBuffer) -> RlsResult<usize> {
        let add_arr = buffer.aad(self.seq);
        let nonce = self.iv.as_array(self.seq);
        buffer.add_explicit_iv(&nonce);
        self.crypto.encrypt(CryptEncodeParam {
            nonce: &nonce,
            iv: &nonce,
            aad: &add_arr,
            seq: &seq,
            buffer: &mut buffer,
        })?;
        Ok(buffer.record_len())
    }

    pub fn decrypt(&mut self, mut buffer: CipherDecodeBuffer) -> RlsResult<usize> {
        let add = buffer.aad(self.seq)?;
        let nonce = buffer.nonce(&mut self.iv, self.seq);
        let len = self.crypto.decrypt(CryptDecodeParam {
            nonce: &nonce,
            iv: &nonce,
            aad: &add,
            seq: &seq,
            buffer: &mut buffer,
        })?;
        Ok(len)
    }
}


#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU64;
    use crate::boring::HashType;
    use crate::buffer::{CipherDecodeBuffer, CipherEncodeBuffer};
    use crate::extend::Aead;
    use crate::suite::cipher::TlsCipher;
    use crate::suite::iv::Iv;
    use crate::{CipherSuite, RecordType};

    #[test]
    fn test_cipher() {
        let mut cipher = TlsCipher::none();
        let key_bs = [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        let ivv = [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        let mac_key = [0; 20];
        let aead = Aead::AES_256_CBC_SHA;
        let suite = &CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA;
        cipher.set_key(&key_bs, &mac_key, &aead, HashType::Sha1).unwrap();
        let iv = Iv::new(&ivv, [].to_vec());
        cipher.set_iv(iv);
        let mut buffer = [0u8; 1024];
        let payload = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 34, 3, 3, 3];
        let record_buffer = CipherEncodeBuffer::new_tls(RecordType::HandShake, &mut buffer, &payload, suite);
        let len = cipher.encrypt(record_buffer).unwrap();
        assert_eq!(&buffer[5..21], ivv);
        assert_eq!(&buffer[..len], [22, 3, 3, 0, 64, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 29, 210, 41, 29, 168, 173, 203, 170, 224, 45, 110, 107, 227, 240, 203, 36, 82, 130, 40, 3, 21, 207, 115, 206, 174, 235, 168, 142, 12, 232, 232, 49, 11, 160, 179, 93, 198, 149, 196, 100, 177, 35, 11, 30, 139, 124, 143, 135]);
        cipher.seq = AtomicU64::new(0);
        let mut out = vec![0; 1024];
        let record_buffer = CipherDecodeBuffer::from_buffer(&buffer[..len], &mut out, suite).unwrap();
        let len = cipher.decrypt(record_buffer).unwrap();
        assert_eq!(&out[..len], payload);
    }

    #[test]
    fn test_tls13_cipher() {
        let mut cipher = TlsCipher::none();
        let key = [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        let iv = [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4];
        let suite = &CipherSuite::TLS_AES_128_GCM_SHA256;
        let aead = suite.aead().unwrap();
        cipher.set_key(&key, &[], &aead, HashType::Sha1).unwrap();
        cipher.set_iv(Iv::new(&iv, Vec::new()));
        let mut buffer = [0u8; 1024];
        let payload = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 34, 3, 3, 3];
        let encoded_buffer = CipherEncodeBuffer::new_tls(RecordType::HandShake, &mut buffer, &payload, suite);
        let len = cipher.encrypt(encoded_buffer).unwrap();
        assert_eq!(&buffer[..len], [23, 3, 3, 0, 33, 34, 40, 91, 27, 49, 27, 234, 48, 61, 80, 240, 83, 57, 50, 173, 18, 215, 175, 31, 86, 15, 170, 121, 14, 214, 229, 157, 92, 45, 134, 62, 241, 235]);

        cipher.seq = AtomicU64::new(0);
        let mut db = [0; 1024];
        let decode_buffer = CipherDecodeBuffer::from_buffer(&buffer[..len], &mut db, suite).unwrap();
        let len = cipher.decrypt(decode_buffer).unwrap();
        assert_eq!(&db[..len - 1], payload);
        assert_eq!(db[len - 1], RecordType::HandShake as u8);
    }
}