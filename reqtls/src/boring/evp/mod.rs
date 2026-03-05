use crate::boring::{CryptDecodeParam, HashType};
mod curve;
pub mod cipher;
mod aead;

use crate::boring::bindings::*;
use crate::error::RlsResult;
pub use aead::AeadCrypto;
pub use cipher::Cipher;
pub use curve::EvpCurve;

use crate::boring::CryptEncodeParam;
use crate::extend::Aead;
use crate::hash::Hmac;
use crate::RlsError;

#[cfg_attr(feature = "export", repr(C))]
#[allow(non_camel_case_types)]
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
}

impl CipherType {
    pub fn as_boring(&self) -> *const EVP_CIPHER {
        match self {
            CipherType::AES_128_CBC => unsafe { EVP_aes_128_cbc() }
            CipherType::AES_192_CBC => unsafe { EVP_aes_192_cbc() }
            CipherType::AES_256_CBC => unsafe { EVP_aes_256_cbc() }
            CipherType::AES_128_ECB => unsafe { EVP_aes_128_ecb() }
            CipherType::AES_192_ECB => unsafe { EVP_aes_192_ecb() }
            CipherType::AES_256_ECB => unsafe { EVP_aes_256_ecb() }
            CipherType::AES_128_CTR => unsafe { EVP_aes_128_ctr() }
            CipherType::AES_192_CTR => unsafe { EVP_aes_192_ctr() }
            CipherType::AES_256_CTR => unsafe { EVP_aes_256_ctr() }
            CipherType::AES_128_GCM => unsafe { EVP_aes_128_gcm() }
            CipherType::AES_192_GCM => unsafe { EVP_aes_192_gcm() }
            CipherType::AES_256_GCM => unsafe { EVP_aes_256_gcm() }
            CipherType::AES_128_OFB => unsafe { EVP_aes_128_ofb() }
            CipherType::AES_192_OFB => unsafe { EVP_aes_192_ofb() }
            CipherType::AES_256_OFB => unsafe { EVP_aes_256_ofb() }
            CipherType::DES_CBC => unsafe { EVP_des_cbc() }
            CipherType::DES_ECB => unsafe { EVP_des_ecb() }
            CipherType::RC4 => unsafe { EVP_rc4() }
        }
    }
}


pub struct CipherCrypto {
    mac_key: Vec<u8>,
    key: Vec<u8>,
    cipher: Cipher,
}

impl CipherCrypto {
    pub fn new(aead: &Aead, key: Vec<u8>, mac: Vec<u8>) -> RlsResult<CipherCrypto> {
        let cipher = match aead {
            Aead::AES_128_CBC_SHA => Cipher::aes_128_cbc(),
            Aead::AES_256_CBC_SHA => Cipher::aes_256_cbc(),
            _ => return Err("not suite, but in suite".into())
        };
        Ok(CipherCrypto {
            mac_key: mac,
            cipher,
            key,
        })
    }

    /// cbc加密块:
    /// ```text
    /// mac = HMAC_SHA1(mac_key, seq_num + record_type + version + len(明文) + plaintext) //20位
    /// ciphertext = AES_CBC(key, iv, plaintext || mac || padding) //pcsk7
    ///```
    pub fn encrypt(&self, param: CryptEncodeParam) -> RlsResult<()> {
        self.cipher.init_encrypt(self.key.as_ptr(), param.iv.as_ptr())?;
        let mut hmac = Hmac::new(&self.mac_key, HashType::Sha1)?;
        hmac.update(param.seq.to_be_bytes())?;
        hmac.update(&param.buffer.head()[..3])?;
        hmac.update((param.buffer.origin_payload().len() as u16).to_be_bytes())?;
        hmac.update(param.buffer.origin_payload())?;
        let mac = hmac.finalize()?;
        let context = param.buffer.origin_payload().as_ptr();
        let out = param.buffer.encrypted_buffer().as_mut_ptr();
        let plain_len = self.cipher.encrypt_update(context, param.buffer.origin_payload().len(), out)?;
        let out = unsafe { out.add(plain_len) };
        let mac_len = self.cipher.encrypt_update(mac.as_ptr(), mac.len(), out)?;
        let padding_len = 16 - (param.buffer.origin_payload().len() + mac.len() + 1) % 16;
        let padding = vec![padding_len as u8; padding_len + 1];
        let out = unsafe { out.add(mac_len) };
        let padding_len = self.cipher.encrypt_update(padding.as_ptr(), padding.len(), out)?;
        let out = unsafe { out.add(padding_len) };
        let final_len = self.cipher.encrypt_finalize(out)?;
        let len = plain_len + mac_len + padding_len + final_len;
        param.buffer.set_encrypted_len(len);
        Ok(())
    }

    pub fn decrypt(&self, param: CryptDecodeParam) -> RlsResult<usize> {
        self.cipher.init_decrypt(self.key.as_ptr(), param.iv.as_ptr())?;
        let context = param.buffer.encrypted_payload().as_ptr();
        let out = param.buffer.decrypted_buffer().as_mut_ptr();
        let out_len = self.cipher.decrypt_update(context, param.buffer.encrypted_payload().len(), out)?;
        let out = unsafe { out.add(out_len) };
        let final_len = self.cipher.decrypt_finalize(out)?;
        let len = out_len + final_len;
        let padding_len = param.buffer.decrypted_buffer()[len - 1] as usize;
        let len = len - padding_len - 1;
        let mut hmac = Hmac::new(&self.mac_key, HashType::Sha1)?;
        hmac.update(param.seq.to_be_bytes())?;
        hmac.update(&param.buffer.head()[..3])?;
        hmac.update((len as u16 - 20).to_be_bytes())?;
        hmac.update(&param.buffer.decrypted_buffer()[..len - 20])?;
        let cmac = hmac.finalize()?;
        let mac = &param.buffer.decrypted_buffer()[len - 20..len - 1];
        let res = unsafe { CRYPTO_memcmp(cmac.as_ptr() as *const _, mac.as_ptr() as *const _, mac.len()) };
        if res != 0 { return Err(RlsError::CipherMacError); }
        Ok(len - 20)
    }
}

#[cfg(test)]
mod tests {
    use crate::boring::evp::CipherCrypto;
    use crate::boring::{CryptDecodeParam, CryptEncodeParam};
    use crate::buffer::{RecordDecodeBuffer, RecordEncodeBuffer};
    use crate::extend::Aead;
    use crate::{base64, rand, Cipher, RecordType};

    #[test]
    fn test_cipher() {
        let mut cipher = Cipher::aes_192_ctr();
        cipher.set_secret_key("1234567812345678", Some("1234567812345678"));
        let res = cipher.encrypt(b"foobar".to_vec()).unwrap();
        println!("{}", base64::b64encode(&res).unwrap());

        let res = cipher.decrypt(res).unwrap();
        println!("{}", String::from_utf8(res).unwrap());
    }

    #[test]
    fn test_cipher_cryptor() {
        let aead = Aead::AES_128_CBC_SHA;
        let key = rand::random::<[u8; 16]>().to_vec();
        let iv = rand::random::<[u8; 16]>();
        println!("{:?}", iv);
        let mut buffer = [0; 1024];
        // payload.extend(&[0; 20]);
        let payload = [1, 2, 3, 4, 5, 61, 2, 3, 4, 5, 6, 7, 8, 9, 23, 23];
        let mac_key = [12; 20];
        let mut record_buffer = RecordEncodeBuffer::new(RecordType::HandShake, &mut buffer, &payload, &aead);
        record_buffer.add_explicit_iv(&iv);

        let crypto = CipherCrypto::new(&aead, key, mac_key.to_vec()).unwrap();
        crypto.encrypt(CryptEncodeParam {
            nonce: &[0; 12],
            iv: &iv,
            aad: &[0; 13],
            seq: &0,
            buffer: &mut record_buffer,
        }).unwrap();
        let len = record_buffer.record_len();
        println!("{}", len);
        println!("{:?}", &buffer[..len + 10]);
        println!("-----------------encrypted---------------------");
        let mut decoded_buffer = vec![0; 1024];
        let mut record_buffer = RecordDecodeBuffer::from_buffer(&buffer[..len], &mut decoded_buffer, &aead).unwrap();
        let len = crypto.decrypt(CryptDecodeParam {
            nonce: &[0; 12],
            iv: &iv,
            aad: &[0; 13],
            seq: &0,
            buffer: &mut record_buffer,
        }).unwrap();
        println!("{:?}", &decoded_buffer[..len]);
    }
}