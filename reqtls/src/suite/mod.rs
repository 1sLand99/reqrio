use std::ops::Range;
use super::record::{RecordBuffer, RecordLayer};
use crate::boring::{CryptParam, Crypto};
use crate::error::{RlsError, RlsResult};
use crate::extend::Aead;
use iv::Iv;
use crate::range::RangeExt;
pub use suite::CipherSuite;

pub mod iv;
mod suite;

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

    pub fn set_key(&mut self, key: &[u8], aead: &Aead) -> RlsResult<()> {
        self.crypto = Crypto::from_aead(key, aead)?;
        Ok(())
    }

    pub fn set_iv(&mut self, iv: Iv) {
        self.iv = iv;
    }

    fn build_aad(&self, layer: &RecordLayer, aead: &Aead) -> RlsResult<[u8; 13]> {
        let mut res = [0; 13];
        res[0..8].copy_from_slice(self.seq.to_be_bytes().as_ref());
        res[8] = layer.context_type.as_u8();
        res[9..11].copy_from_slice(&layer.version.as_u16().to_be_bytes()); // TLS1.2
        let payload = layer.messages[0].payload().ok_or(RlsError::PayloadNone)?;
        let payload_len = payload.value.len() as u16 - aead.explicit_len() as u16 - 16;
        res[11..13].copy_from_slice(&payload_len.to_be_bytes());
        Ok(res)
    }

    pub fn encrypt(&mut self, mut buffer: RecordBuffer) -> RlsResult<usize> {
        let add_arr = buffer.aad(self.seq);
        let nonce = self.iv.as_array(self.seq);
        buffer.add_explicit_iv(&nonce);
        let len = self.crypto.encrypt(CryptParam {
            aead: buffer.aead,
            nonce: &nonce,
            iv: &nonce,
            aad: &add_arr,
            payload: &mut buffer.payload,
        })?;
        buffer.set_payload_len(len);
        self.seq += 1;
        Ok(len + 5)
    }

    pub fn decrypt<'a>(&mut self, record: &'a mut RecordLayer<'a>, aead: &Aead) -> RlsResult<Range<usize>> {
        let add_arr = self.build_aad(record, aead)?;
        let payload = record.messages[0].payload_mut().ok_or(RlsError::PayloadNone)?;
        self.iv.set_explicit(payload.explicit_iv(aead).to_vec());
        let nonce = match aead {
            Aead::AES_128_GCM | Aead::AES_256_GCM => self.iv.decrypting_iv(),
            Aead::ChaCha20_POLY1305 => self.iv.as_array(self.seq),
            Aead::AES_128_CBC_SHA | Aead::AES_256_CBC_SHA => self.iv.decrypting_iv(),
            _ => return Err("gen nonce none".into())
        };
        let len = self.crypto.decrypt(CryptParam {
            aead,
            nonce: &nonce,
            iv: &nonce,
            aad: &add_arr,
            payload,
        })?;
        self.seq += 1;
        Ok(aead.payload_range(len).add(5))
    }
}


#[cfg(test)]
mod tests {
    use crate::suite::iv::Iv;
    use crate::suite::TlsCipher;
    use crate::extend::Aead;
    use crate::message::Payload;
    use crate::{rand, Message, RecordLayer, RecordType, Version};
    use crate::record::RecordBuffer;

    #[test]
    fn test_cipher() {
        let mut cipher = TlsCipher::none();
        let key_bs = rand::random::<[u8; 32]>().to_vec();
        let iv = rand::random::<[u8; 16]>();
        let explicit = rand::random::<[u8; 8]>();
        let aead = Aead::AES_256_CBC_SHA;
        cipher.set_key(&key_bs, &aead).unwrap();
        let iv = Iv::new(&iv, explicit.to_vec());
        cipher.set_iv(iv);
        let mut buffer = [0u8; 1024];
        let mut record_buffer = RecordBuffer::from_buffer(&aead, &mut buffer);
        record_buffer.set_head(RecordType::HandShake, Version::TLS_1_2);
        record_buffer.set_payload(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 0]);
        let len = cipher.encrypt(record_buffer).unwrap();
        println!("{:?}", &buffer[..len + 10]);
        cipher.seq = 0;
        let mut record_buffer = RecordLayer {
            context_type: RecordType::HandShake,
            version: Version::TLS_1_2,
            len: 0,
            messages: vec![Message::Payload(Payload::from_slice(&mut buffer[5..len]))],
        };
        let pdr = cipher.decrypt(&mut record_buffer, &aead).unwrap();
        println!("{:?}", &buffer[pdr]);
    }
}