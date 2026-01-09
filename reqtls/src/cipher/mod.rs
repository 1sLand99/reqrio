use std::ops::Range;
use super::record::{RecordBuffer, RecordLayer};
use crate::boring::{CryptParam, Cryptor};
use crate::error::{RlsError, RlsResult};
use crate::extend::Aead;
use iv::Iv;
use crate::range::RangeExt;

pub mod iv;
// pub mod key;
pub mod suite;

pub struct Cipher {
    cryptor: Cryptor,
    iv: Iv,
    seq: u64,
}


impl Cipher {
    pub fn none() -> Cipher {
        Cipher {
            cryptor: Cryptor::None,
            iv: Iv::new(&vec![], vec![]),
            seq: 0,
        }
    }

    pub fn set_key(&mut self, key: &[u8], aead: &Aead) -> RlsResult<()> {
        self.cryptor = Cryptor::from_aead(key, aead)?;
        Ok(())
    }

    pub fn set_iv(&mut self, iv: Iv) {
        self.iv = iv;
    }

    fn build_aad(&self, layer: &RecordLayer, aead: &Aead) -> RlsResult<[u8; 13]> {
        let mut res = [0; 13];
        res[0..8].copy_from_slice(self.seq.to_be_bytes().as_ref());
        res[8] = layer.context_type.as_u8();
        res[9..11].copy_from_slice(&layer.version.as_bytes()); // TLS1.2
        let payload = layer.messages[0].payload().ok_or(RlsError::PayloadNone)?;
        let payload_len = payload.value.len() as u16 - aead.explicit_len() as u16 - 16;
        res[11..13].copy_from_slice(&payload_len.to_be_bytes());
        Ok(res)
    }

    pub fn encrypt<'a>(&mut self, mut buffer: RecordBuffer) -> RlsResult<usize> {
        let add_arr = buffer.aad(self.seq);
        let nonce = self.iv.as_array(self.seq);
        buffer.add_explicit_iv(&nonce.as_ref()[4..]);
        let len = self.cryptor.encrypt(CryptParam {
            aead: buffer.aead,
            nonce: &self.iv.as_array(self.seq),
            iv: &[],
            aad: &add_arr,
            payload: &mut buffer.payload,
        })?;
        buffer.set_payload_len(len);
        self.seq += 1;
        Ok(len + 5)
    }

    pub fn decrypt<'a>(&mut self, record: &'a mut RecordLayer<'a>, aead: &Aead) -> RlsResult<Range<usize>> {
        let add_arr = self.build_aad(&record, aead)?;
        let payload = record.messages[0].payload_mut().ok_or(RlsError::PayloadNone)?;
        self.iv.set_explicit(payload.explicit(aead).to_vec());
        let nonce = match aead {
            Aead::AES_128_GCM | Aead::AES_256_GCM => self.iv.as_ref(),
            Aead::ChaCha20_POLY1305 => self.iv.as_array(self.seq),
            _ => return Err("gen nonce none".into())
        };
        let len = self.cryptor.decrypt(CryptParam {
            aead,
            nonce: &nonce,
            iv: &[],
            aad: &add_arr,
            payload,
        })?;
        self.seq += 1;
        Ok(aead.payload_range(len).add(5))
    }
}


#[cfg(test)]
mod tests {
    use crate::cipher::iv::Iv;
    use crate::cipher::Cipher;
    use crate::extend::Aead;
    use crate::message::Payload;
    use crate::version::VersionKind;
    use crate::{rand, Message, RecordLayer, RecordType, Version};

    #[test]
    fn test_cipher() {
        let mut cipher = Cipher::none();
        let key_bs = rand::random::<[u8; 32]>().to_vec();
        let iv = rand::random::<[u8; 12]>();
        // let explicit = rand::random::<[u8; 8]>();
        let aead = Aead::ChaCha20_POLY1305;
        cipher.set_key(&key_bs, &aead).unwrap();
        let iv = Iv::new(&iv, vec![]);
        cipher.set_iv(iv);
        let mut payload_buffer = [0; 37];
        payload_buffer[5..21].copy_from_slice(&rand::random::<[u8; 16]>());
        println!("{:?}", payload_buffer);
        let mut layer = RecordLayer {
            context_type: RecordType::HandShake,
            version: Version::new(VersionKind::TLS_1_2 as u16),
            len: 0,
            messages: vec![Message::Payload(Payload::from_slice(&mut payload_buffer[5..]))],
        };
        cipher.encrypt(&mut layer, &aead).unwrap();
        println!("{:?}", payload_buffer);
        cipher.seq = 0;
        let mut layer = RecordLayer {
            context_type: RecordType::HandShake,
            version: Version::new(VersionKind::TLS_1_2 as u16),
            len: 0,
            messages: vec![Message::Payload(Payload::from_slice(&mut payload_buffer[5..]))],
        };
        cipher.decrypt(&mut layer, &aead).unwrap();
        println!("{:?}", payload_buffer);
        // cipher.encrypt(&mut layer).unwrap(); //单独运行这个不报错，在前面的Finish后会偶尔会报错
        // let _res = cipher.decrypt(layer).unwrap();
    }
}