use crate::boring::AeadDir;
use crate::buffer::{CipherEncodeBuffer, TlsDecodeBuffer};
use crate::error::RlsResult;
use crate::{AeadCtx, CipherSuite};

pub struct TlsCipher {
    ctx: AeadCtx,
}


impl TlsCipher {
    pub fn none() -> TlsCipher {
        TlsCipher {
            ctx: AeadCtx::none(),
        }
    }

    pub fn set_key(&mut self, key: &[u8], iv: &[u8], suite: &'static CipherSuite, dir: AeadDir) -> RlsResult<()> {
        self.ctx.init_aead(suite.aead, dir, key, iv)?;
        self.ctx.seq = 0;
        Ok(())
    }

    pub fn encrypt(&mut self, seq: Option<u64>, mut buffer: CipherEncodeBuffer) -> RlsResult<usize> {
        let seq_num = if let Some(seq) = seq { seq } else { self.ctx.seq };
        let add_arr = buffer.aad(seq_num);
        let nonce = self.ctx.iv.as_array(seq_num, None);
        buffer.add_explicit_iv(&nonce);
        self.ctx.seal(&nonce, &add_arr, &mut buffer)?;
        if seq.is_none() { self.ctx.seq += 1; }
        Ok(buffer.record_len())
    }

    pub fn decrypt(&mut self, seq: Option<u64>, mut buffer: TlsDecodeBuffer) -> RlsResult<usize> {
        let seq_num = if let Some(seq) = seq { seq } else { self.ctx.seq };
        let aad = buffer.aad(seq_num)?;
        let nonce = buffer.nonce(&self.ctx.iv, seq_num);
        let len = self.ctx.open(&nonce, &aad, &mut buffer)?;
        if seq.is_none() { self.ctx.seq += 1; }
        Ok(len)
    }

    #[cfg(feature = "quic")]
    pub fn is_null(&self) -> bool {
        self.ctx.is_null()
    }
}


#[cfg(test)]
mod tests {
    use crate::boring::AeadDir;
    use crate::buffer::{CipherEncodeBuffer, TlsDecodeBuffer};
    use crate::suite::cipher::TlsCipher;
    use crate::{CipherSuite, RecordType};

    #[test]
    fn test_cipher() {
        let mut cipher = TlsCipher::none();
        let ivv = [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        let key = [
            [0; 20].as_slice(),
            [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8].as_slice()
        ].concat();
        let suite = &CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA;
        cipher.set_key(&key, &ivv, suite, AeadDir::Seal).unwrap();
        // let iv = Iv::new().with_init(&ivv);
        // cipher.set_iv(iv);
        let mut buffer = [0u8; 1024];
        let payload = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 34, 3, 3, 3];
        let record_buffer = CipherEncodeBuffer::new_tls(RecordType::HandShake, &mut buffer, &payload, suite);
        let len = cipher.encrypt(None, record_buffer).unwrap();
        assert_eq!(&buffer[5..21], ivv);
        assert_eq!(&buffer[..len], [22, 3, 3, 0, 64, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 29, 210, 41, 29, 168, 173, 203, 170, 224, 45, 110, 107, 227, 240, 203, 36, 82, 130, 40, 3, 21, 207, 115, 206, 174, 235, 168, 142, 12, 232, 232, 49, 11, 160, 179, 93, 198, 149, 196, 100, 177, 35, 11, 30, 139, 124, 143, 135]);
        cipher.ctx.seq = 0;
        let mut out = vec![0; 1024];
        cipher.set_key(&key, &ivv, suite, AeadDir::Open).unwrap();
        let record_buffer = TlsDecodeBuffer::from_buffer(&buffer[..len], &mut out, suite).unwrap();
        let len = cipher.decrypt(None, record_buffer).unwrap();
        assert_eq!(&out[..len], payload);
    }

    #[test]
    fn test_tls13_cipher() {
        let mut cipher = TlsCipher::none();
        let key = [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        let iv = [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4];
        let suite = &CipherSuite::TLS_AES_128_GCM_SHA256;
        cipher.set_key(&key, &iv, suite, AeadDir::Open).unwrap();
        let mut buffer = [0u8; 1024];
        let payload = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 34, 3, 3, 3];
        let encoded_buffer = CipherEncodeBuffer::new_tls(RecordType::HandShake, &mut buffer, &payload, suite);
        let len = cipher.encrypt(None, encoded_buffer).unwrap();
        assert_eq!(&buffer[..len], [23, 3, 3, 0, 33, 34, 40, 91, 27, 49, 27, 234, 48, 61, 80, 240, 83, 57, 50, 173, 18, 215, 175, 31, 86, 15, 170, 121, 14, 214, 229, 157, 92, 45, 134, 62, 241, 235]);

        cipher.ctx.seq = 0;
        let mut db = [0; 1024];
        let decode_buffer = TlsDecodeBuffer::from_buffer(&buffer[..len], &mut db, suite).unwrap();
        let len = cipher.decrypt(None, decode_buffer).unwrap();
        assert_eq!(&db[..len - 1], payload);
        assert_eq!(db[len - 1], RecordType::HandShake as u8);
    }
}