use crate::boring::{CryptDecodeParam, CryptEncodeParam, Crypto};
use crate::buffer::{RecordDecodeBuffer, RecordEncodeBuffer};
use crate::error::RlsResult;
use crate::extend::Aead;
use crate::suite::iv::Iv;
use crate::{HashType, Version};

pub struct TlsCipher {
    crypto: Crypto,
    iv: Iv,
    seq: u64,
}


impl TlsCipher {
    pub fn none() -> TlsCipher {
        TlsCipher {
            crypto: Crypto::None,
            iv: Iv::new(&[], vec![]),
            seq: 0,
        }
    }

    pub fn set_key(&mut self, key: &[u8], mac_key: &[u8], aead: &Aead, hash: HashType) -> RlsResult<()> {
        self.crypto = Crypto::from_aead(key, mac_key, aead, hash)?;
        self.seq = 0;
        Ok(())
    }

    pub fn set_iv(&mut self, iv: Iv) {
        self.iv = iv;
    }


    pub fn encrypt(&mut self, mut buffer: RecordEncodeBuffer) -> RlsResult<usize> {
        let add_arr = buffer.aad(self.seq);
        let nonce = self.iv.as_array(self.seq);
        buffer.add_explicit_iv(&nonce);
        println!("aad: {:?}; nonce: {:?}", add_arr, nonce);
        self.crypto.encrypt(CryptEncodeParam {
            nonce: &nonce,
            iv: &nonce,
            aad: &add_arr,
            seq: &self.seq,
            buffer: &mut buffer,
        })?;
        self.seq += 1;
        Ok(buffer.record_len())
    }

    pub fn decrypt(&mut self, mut buffer: RecordDecodeBuffer) -> RlsResult<usize> {
        let add = buffer.aad(self.seq)?;
        self.iv.set_explicit(buffer.explicit_iv().to_vec());
        let nonce = match buffer.aead() {
            Aead::AES_128_GCM | Aead::AES_256_GCM => match *buffer.version() {
                Version::TLS_1_3 => self.iv.as_array(self.seq),
                _ => self.iv.decrypting_iv()
            },
            Aead::ChaCha20_POLY1305 => self.iv.as_array(self.seq),
            Aead::AES_128_CBC_SHA | Aead::AES_256_CBC_SHA => self.iv.decrypting_iv(),
            _ => return Err("gen nonce none".into())
        };
        println!("seq: {}; add: {:?}; nonce: {:?}", self.seq, add, nonce);
        let len = self.crypto.decrypt(CryptDecodeParam {
            nonce: &nonce,
            iv: &nonce,
            aad: &add,
            seq: &self.seq,
            buffer: &mut buffer,
        })?;
        self.seq += 1;
        Ok(len)
    }
}


#[cfg(test)]
mod tests {
    use crate::boring::HashType;
    use crate::buffer::{RecordDecodeBuffer, RecordEncodeBuffer};
    use crate::extend::Aead;
    use crate::suite::cipher::TlsCipher;
    use crate::suite::iv::Iv;
    use crate::{rand, RecordType, Version};

    #[test]
    fn test_cipher() {
        let mut cipher = TlsCipher::none();
        let key_bs = rand::random::<[u8; 32]>().to_vec();
        let ivv = rand::random::<[u8; 16]>();
        let explicit = rand::random::<[u8; 0]>();
        let mac_key = rand::random::<[u8; 20]>();
        let aead = Aead::AES_256_CBC_SHA;
        cipher.set_key(&key_bs, &mac_key, &aead, HashType::Sha1).unwrap();
        let iv = Iv::new(&ivv, explicit.to_vec());
        cipher.set_iv(iv);
        let mut buffer = [0u8; 1024];
        let payload = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 34, 3, 3, 3];
        let record_buffer = RecordEncodeBuffer::new(RecordType::HandShake, &Version::TLS_1_2, &mut buffer, &payload, &aead);
        let len = cipher.encrypt(record_buffer).unwrap();
        assert_eq!(&buffer[5..21], ivv);
        println!("{:?}", &buffer[..len + 10]);
        cipher.seq = 0;
        let mut out = vec![0; 1024];
        let record_buffer = RecordDecodeBuffer::from_buffer(&buffer[..len], &mut out, &aead, &Version::TLS_1_2).unwrap();
        let len = cipher.decrypt(record_buffer).unwrap();
        println!("{:?}", &out[..len]);
        assert_eq!(&out[..len], payload);
    }

    #[test]
    fn test_tls13_cipher() {
        let mut cipher = TlsCipher::none();
        let key = rand::random::<[u8; 16]>();
        let iv = rand::random::<[u8; 12]>();
        let aead = Aead::AES_128_GCM;
        cipher.set_key(&key, &[], &aead, HashType::Sha1).unwrap();
        cipher.set_iv(Iv::new(&iv, Vec::new()));
        let mut buffer = [0u8; 1024];
        let payload = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 34, 3, 3, 3];
        let encoded_buffer = RecordEncodeBuffer::new(RecordType::HandShake, &Version::TLS_1_3, &mut buffer, &payload, &aead);
        let len = cipher.encrypt(encoded_buffer).unwrap();
        println!("{} {:?}", len, &buffer[..len]);

        cipher.seq = 0;
        let mut db = [0; 1024];
        let decode_buffer = RecordDecodeBuffer::from_buffer(&buffer[..len], &mut db, &aead, &Version::TLS_1_3).unwrap();
        let len = cipher.decrypt(decode_buffer).unwrap();
        assert_eq!(&db[..len - 1], payload);
        assert_eq!(db[len - 1], RecordType::HandShake as u8);
    }
}