use crate::boring::{BoringResExt, CryptDecodeParam};
mod curve;
pub mod cipher;
mod aead;

use crate::boring::bindings::*;
use crate::error::RlsResult;
pub use aead::AeadCrypto;
pub use cipher::Cipher;
pub use curve::EvpCurve;
use std::ptr::null_mut;

use crate::boring::CryptEncodeParam;
use crate::extend::Aead;
use crate::ffi::CPointer;
use crate::{hmac, rand, RlsError};

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
    ctx: CPointer<EVP_CIPHER_CTX>,
    mac_key: [u8; 20],
    key: Vec<u8>,
    evp_cipher: CipherType,
}

impl CipherCrypto {
    pub fn new(aead: &Aead, key: Vec<u8>) -> RlsResult<CipherCrypto> {
        let evp_cipher = match aead {
            Aead::AES_128_CBC_SHA => CipherType::AES_128_CBC,
            Aead::AES_256_CBC_SHA => CipherType::AES_256_CBC,
            _ => return Err("not suite, but in suite".into())
        };
        let ctx = CPointer::new(unsafe { EVP_CIPHER_CTX_new() });
        if ctx.is_null() { return Err(RlsError::InitEvpCtxError); }
        Ok(CipherCrypto {
            ctx,
            mac_key: rand::random(),
            evp_cipher,
            key,
        })
    }

    /// cbc加密块:
    /// ```text
    /// mac = HMAC_SHA1(mac_key, seq_num + hdr + plaintext) //20位
    /// ciphertext = AES_CBC(key, iv, plaintext || mac || padding) //pcsk7
    ///```
    pub fn encrypt(&self, param: CryptEncodeParam) -> RlsResult<()> {
        unsafe { EVP_EncryptInit_ex(self.ctx.as_mut_ptr(), self.evp_cipher.as_boring(), null_mut(), self.key.as_ptr(), param.iv.as_ptr()) }.ok(RlsError::CipherCryptError)?;
        let mut out_len = 0;
        unsafe {
            EVP_EncryptUpdate(
                self.ctx.as_mut_ptr(),
                param.buffer.encrypted_buffer().as_mut_ptr(),
                &mut out_len,
                param.buffer.origin_payload().as_ptr(),
                param.buffer.origin_payload().len() as i32)
        }.ok(RlsError::CipherEncryptError)?;
        let mut final_len = 0;
        unsafe {
            EVP_EncryptFinal_ex(
                self.ctx.as_mut_ptr(),
                param.buffer.encrypted_buffer()[out_len as usize..].as_mut_ptr(),
                &mut final_len,
            )
        }.ok(RlsError::CipherEncryptError)?;
        let len = (16 + out_len + final_len) as usize;
        println!("auth_data={:?}", param.buffer.auth_data(len));
        let mac = hmac::hmac_sha1(self.mac_key, param.buffer.auth_data(len))?;
        println!("111{:?}", mac);
        param.buffer.add_verify_mac(len, &mac);
        param.buffer.set_encrypted_len(len + 20);
        Ok(())
    }

    pub fn decrypt(&self, param: CryptDecodeParam) -> RlsResult<usize> {
        println!("auth_data={:?}", param.buffer.auto_data());
        let mac = param.buffer.verify_mac();
        // 2. 校验 HMAC (必须先于解密)
        let computed_mac = hmac::hmac_sha1(self.mac_key, param.buffer.auto_data())?;
        // 使用恒定时间比较 (Constant-time comparison) 防止侧信道攻击
        let res = unsafe { CRYPTO_memcmp(computed_mac.as_ptr() as *const _, mac.as_ptr() as *const _, mac.len()) };
        if res != 0 { return Err(RlsError::CipherMacError); }
        // 3. 初始化解密
        unsafe { EVP_DecryptInit_ex(self.ctx.as_mut_ptr(), self.evp_cipher.as_boring(), null_mut(), self.key.as_ptr(), param.iv.as_ptr()) }.ok(RlsError::CipherCryptError)?;

        // 4. 执行解密
        let mut out_len = 0i32;
        let mut final_len = 0i32;
        unsafe {
            EVP_DecryptUpdate(
                self.ctx.as_mut_ptr(),
                param.buffer.decrypted_buffer().as_mut_ptr(),
                &mut out_len,
                param.buffer.encrypted_payload().as_ptr(),
                param.buffer.encrypted_payload().len() as i32,
            )
        }.ok(RlsError::CipherDecryptError)?;
        unsafe {
            EVP_DecryptFinal_ex(
                self.ctx.as_mut_ptr(),
                param.buffer.decrypted_buffer().as_mut_ptr().add(out_len as usize),
                &mut final_len,
            )
        }.ok(RlsError::CipherDecryptError)?;
        Ok((out_len + final_len) as usize)
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
        // println!("{:?}", iv);
        let mut buffer = [0; 1024];
        // payload.extend(&[0; 20]);
        let payload = [1, 2, 3, 4, 5, 61, 2, 3, 4, 5, 6, 7, 8, 9, 23, 23];
        let mut record_buffer = RecordEncodeBuffer::new(RecordType::HandShake, &mut buffer, &payload, &aead);
        record_buffer.add_explicit_iv(&iv);

        let crypto = CipherCrypto::new(&aead, key).unwrap();
        crypto.encrypt(CryptEncodeParam {
            nonce: &[0; 12],
            iv: &iv,
            aad: &[0; 13],
            buffer: &mut record_buffer,
        }).unwrap();
        let len = record_buffer.record_len();
        println!("{:?}", &buffer[..len + 10]);
        let mut decoded_buffer = vec![0; 1024];
        let mut record_buffer = RecordDecodeBuffer::from_buffer(&buffer[..len], &mut decoded_buffer, &aead).unwrap();
        let len = crypto.decrypt(CryptDecodeParam {
            nonce: &[0; 12],
            iv: &iv,
            aad: &[0; 13],
            buffer: &mut record_buffer,
        }).unwrap();
        println!("{:?}", &decoded_buffer[..len]);
    }
}