use crate::boring::{CryptDecodeParam, HashType};
mod curve;
pub mod cipher;
mod aead;
mod error;
mod pkey;
mod pkey_ctx;

use crate::boring::bindings::*;
use crate::error::RlsResult;
pub use aead::AeadCtx;
pub use cipher::Cipher;
pub use curve::EvpCurve;

use crate::boring::CryptEncodeParam;
use crate::cipher::CipherError;
use crate::extend::Aead;
use crate::hash::Hmac;
pub use error::EvpError;
pub use pkey::PKey;
use pkey::PKEY;
pub use pkey_ctx::PKeyCtx;
pub use pkey_ctx::PKeyError;

#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
pub enum CipherType {
    AES_128_CBC = 0,
    AES_192_CBC = 1,
    AES_256_CBC = 2,
    AES_128_ECB = 3,
    AES_192_ECB = 4,
    AES_256_ECB = 5,
    AES_128_CTR = 6,
    AES_192_CTR = 7,
    AES_256_CTR = 8,
    AES_128_GCM = 9,
    AES_192_GCM = 10,
    AES_256_GCM = 11,
    AES_128_OFB = 12,
    AES_192_OFB = 13,
    AES_256_OFB = 14,
    DES_CBC = 15,
    DES_ECB = 16,
    RC4 = 17,
    SM4_ECB = 18,
    SM4_CBC = 19,
    SM4_CTR = 20,
    SM4_CTR_32 = 21,
    SM4_OFB = 22,
    SM4_CFB = 23,
    SM4_GCM = 27,
    DES_DED3_CBC = 24,
    DES_DED3_ECB = 25,
    CHACHA20_POLY1305 = 26,
}


pub struct CipherCrypto {
    mac_key: Vec<u8>,
    cipher: Cipher,
    hash: HashType,
}

impl CipherCrypto {
    pub fn new(aead: &Aead, key: Vec<u8>, mac: Vec<u8>, hash: HashType) -> RlsResult<CipherCrypto> {
        let cipher = match aead {
            Aead::AES_128_CBC_SHA => Cipher::aes_128_cbc(),
            Aead::AES_256_CBC_SHA => Cipher::aes_256_cbc(),
            Aead::AES_128_CBC_SHA256 => Cipher::aes_128_cbc(),
            Aead::AES_256_CBC_SHA384 => Cipher::aes_256_cbc(),
            _ => return Err("not suite, but in suite".into())
        }.with_secret_key(key, None);
        Ok(CipherCrypto {
            mac_key: mac,
            cipher,
            hash,
        })
    }

    /// cbc加密块:
    /// ```text
    /// mac = HMAC_SHA1(mac_key, seq_num + record_type + version + len(明文) + plaintext) //20位
    /// ciphertext = AES_CBC(key, iv, plaintext || mac || padding) //pcsk7
    ///```
    pub fn encrypt(&self, param: CryptEncodeParam) -> RlsResult<()> {
        self.cipher.init_cipher(param.iv, 1)?;
        let mut hmac = Hmac::new(&self.mac_key, self.hash)?;
        hmac.update(param.seq.to_be_bytes())?;
        hmac.update(&param.buffer.head()[..3])?;
        let payload = param.buffer.payload();
        hmac.update((payload.origin_payload().len() as u16).to_be_bytes())?;
        hmac.update(payload.origin_payload())?;
        let mac = hmac.finalize()?;
        let context = payload.origin_payload().as_ptr();
        let out = payload.encoded_payload().as_mut_ptr();
        let plain_len = self.cipher.update(context, payload.origin_payload().len(), out)?;
        let out = unsafe { out.add(plain_len) };
        let mac_len = self.cipher.update(mac.as_ptr(), mac.len(), out)?;
        let padding_len = 16 - (payload.origin_payload().len() + mac.len() + 1) % 16;
        let padding = vec![padding_len as u8; padding_len + 1];
        let out = unsafe { out.add(mac_len) };
        let padding_len = self.cipher.update(padding.as_ptr(), padding.len(), out)?;
        let out = unsafe { out.add(padding_len) };
        let final_len = self.cipher.finalize(out)?;
        let len = plain_len + mac_len + padding_len + final_len;
        param.buffer.set_encrypted_len(len);
        Ok(())
    }

    pub fn decrypt(&self, param: CryptDecodeParam) -> RlsResult<usize> {
        self.cipher.init_cipher(param.iv, 0)?;
        let context = param.buffer.encrypted_payload().as_ptr();
        let out = param.buffer.decrypted_buffer().as_mut_ptr();
        let out_len = self.cipher.update(context, param.buffer.encrypted_payload().len(), out)?;
        let out = unsafe { out.add(out_len) };
        let final_len = self.cipher.finalize(out)?;
        let len = out_len + final_len;
        let padding_len = param.buffer.decrypted_buffer()[len - 1] as usize;
        let len = len - padding_len - 1;
        let mut hmac = Hmac::new(&self.mac_key, self.hash)?;
        hmac.update(param.seq.to_be_bytes())?;
        hmac.update(&param.buffer.head()[..3])?;
        hmac.update((len as u16 - self.hash.hash_size() as u16).to_be_bytes())?;
        hmac.update(&param.buffer.decrypted_buffer()[..len - self.hash.hash_size()])?;
        let cmac = hmac.finalize()?;
        let mac = &param.buffer.decrypted_buffer()[len - self.hash.hash_size()..len];
        let res = unsafe { CRYPTO_memcmp(cmac.as_ptr() as *const _, mac.as_ptr() as *const _, mac.len()) };
        if res != 0 { return Err(CipherError::InvalidMac.into()); }
        Ok(len - self.hash.hash_size())
    }
}

#[cfg(test)]
mod tests {
    use crate::boring::evp::CipherCrypto;
    use crate::boring::{CryptDecodeParam, CryptEncodeParam};
    use crate::buffer::{CipherDecodeBuffer, CipherEncodeBuffer};
    use crate::{CipherSuite, RecordType};

    fn test_cipher_tls(suite: &'static CipherSuite, key: &[u8], en: &[u8]) {
        let iv = [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        let payload = [1, 2, 3, 4, 5, 61, 2, 3, 4, 5, 6, 7, 8, 9, 23, 23];
        let mac_key = vec![12; suite.mac_key_size];
        let mut buffer = [0; 1024];
        let mut record_buffer = CipherEncodeBuffer::new_tls(RecordType::HandShake, &mut buffer, &payload, suite);
        record_buffer.add_explicit_iv(&iv);


        let crypto = CipherCrypto::new(&suite.aead().unwrap(), key.to_vec(), mac_key.to_vec(), suite.mac_hash()).unwrap();
        crypto.encrypt(CryptEncodeParam {
            nonce: &[0; 12],
            iv: &iv,
            aad: &[0; 13],
            seq: &0,
            buffer: &mut record_buffer,
        }).unwrap();
        let len = record_buffer.record_len();
        assert_eq!(&buffer[..len], en);


        let mut decoded_buffer = vec![0; 1024];
        let mut record_buffer = CipherDecodeBuffer::from_buffer(&buffer[..len], &mut decoded_buffer, suite).unwrap();
        let len = crypto.decrypt(CryptDecodeParam {
            nonce: &[0; 12],
            iv: &iv,
            aad: &[0; 13],
            seq: &0,
            buffer: &mut record_buffer,
        }).unwrap();
        assert_eq!(decoded_buffer[..len], payload);
    }

    #[test]
    fn test_cipher_cryptor() {
        let key = [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8].to_vec();
        test_cipher_tls(&CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, &key, &[22, 3, 3, 0, 64, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 225, 181, 85, 149, 189, 100, 192, 39, 33, 30, 205, 22, 123, 49, 172, 97, 106, 123, 166, 131, 129, 167, 149, 187, 174, 174, 240, 122, 9, 87, 56, 140, 117, 152, 228, 72, 33, 112, 254, 70, 101, 122, 70, 56, 86, 138, 18, 134]);
        test_cipher_tls(&CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, &key, &[22, 3, 3, 0, 80, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 225, 181, 85, 149, 189, 100, 192, 39, 33, 30, 205, 22, 123, 49, 172, 97, 150, 39, 188, 217, 227, 123, 176, 202, 171, 118, 173, 133, 177, 212, 23, 239, 79, 83, 238, 222, 83, 155, 116, 15, 213, 225, 52, 26, 134, 201, 207, 232, 194, 72, 163, 90, 108, 33, 90, 207, 135, 156, 79, 245, 245, 89, 69, 218]);


        let key = [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8].to_vec();
        test_cipher_tls(&CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, &key, &[22, 3, 3, 0, 64, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 14, 154, 194, 131, 254, 83, 135, 224, 182, 116, 28, 102, 151, 64, 116, 65, 233, 40, 102, 87, 64, 5, 139, 184, 61, 216, 62, 94, 54, 212, 193, 146, 8, 193, 18, 124, 254, 208, 135, 126, 57, 190, 219, 84, 217, 103, 135, 96]);
        test_cipher_tls(&CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, &key, &[22, 3, 3, 0, 96, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 14, 154, 194, 131, 254, 83, 135, 224, 182, 116, 28, 102, 151, 64, 116, 65, 69, 90, 210, 242, 249, 68, 56, 215, 228, 165, 35, 39, 182, 148, 179, 128, 14, 191, 51, 49, 128, 170, 146, 205, 56, 8, 34, 192, 78, 178, 233, 122, 153, 25, 193, 53, 84, 243, 227, 111, 212, 236, 62, 214, 206, 240, 42, 232, 245, 246, 24, 145, 92, 181, 124, 12, 172, 150, 19, 195, 58, 123, 93, 40]);
    }
}