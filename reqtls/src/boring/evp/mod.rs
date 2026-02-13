#[cfg(feature = "tls")]
use crate::boring::BoringResExt;
#[cfg(feature = "tls")]
mod curve;
pub mod cipher;
#[cfg(feature = "tls")]
mod aead;

#[cfg(feature = "tls")]
use std::ptr::null_mut;
pub use cipher::Cipher;
#[cfg(feature = "tls")]
pub use curve::EvpCurve;
#[cfg(feature = "tls")]
pub use aead::AeadCrypto;
use crate::boring::bindings::*;
#[cfg(feature = "tls")]
use crate::error::RlsResult;

#[cfg(feature = "tls")]
use crate::extend::Aead;
#[cfg(feature = "tls")]
use crate::{hmac, rand, RlsError};
#[cfg(feature = "tls")]
use crate::boring::CryptParam;
#[cfg(feature = "tls")]
use crate::ffi::CPointer;

#[allow(non_camel_case_types)]
pub enum CipherType {
    AES_128_CBC,
    AES_192_CBC,
    AES_256_CBC,
    AES_128_ECB,
    AES_192_ECB,
    AES_256_ECB,
    AES_128_CTR,
    AES_192_CTR,
    AES_256_CTR,
    AES_128_GCM,
    AES_192_GCM,
    AES_256_GCM,
    AES_128_OFB,
    AES_192_OFB,
    AES_256_OFB,
    DES_CBC,
    DES_ECB,
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
        }
    }
}


#[cfg(feature = "tls")]
pub struct CipherCrypto {
    ctx: CPointer<EVP_CIPHER_CTX>,
    mac_key: [u8; 20],
    key: Vec<u8>,
    evp_cipher: CipherType,
}

#[cfg(feature = "tls")]
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
    pub fn encrypt(&self, param: CryptParam) -> RlsResult<usize> {
        unsafe { EVP_EncryptInit_ex(self.ctx.as_mut_ptr(), self.evp_cipher.as_boring(), null_mut(), self.key.as_ptr(), param.iv.as_ptr()) }.ok(RlsError::CipherCryptError)?;
        let mut out_len = 0;
        unsafe {
            EVP_EncryptUpdate(
                self.ctx.as_mut_ptr(),
                param.payload.encrypting_out(param.aead).as_mut_ptr(),
                &mut out_len,
                param.payload.encrypting_in(param.aead).as_ptr(),
                param.payload.len as i32)
        }.ok(RlsError::CipherEncryptError)?;
        let mut final_len = 0;
        unsafe {
            EVP_EncryptFinal_ex(
                self.ctx.as_mut_ptr(),
                param.payload.value[16 + out_len as usize..].as_mut_ptr(),
                &mut final_len,
            )
        }.ok(RlsError::CipherEncryptError)?;
        let len = (16 + out_len + final_len) as usize;
        let mac = hmac::hmac_sha1(self.mac_key, &param.payload.value[..len])?;
        param.payload.value[len..len + 20].copy_from_slice(&mac);
        Ok((16 + out_len + final_len + 20) as usize)
    }

    pub fn decrypt(&self, param: CryptParam) -> RlsResult<usize> {
        let auth_data = &param.payload.value[..param.payload.value.len() - 20];
        let mac = &param.payload.value[param.payload.value.len() - 20..];
        // 2. 校验 HMAC (必须先于解密)
        let computed_mac = hmac::hmac_sha1(self.mac_key, auth_data)?;
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
                param.payload.decrypting_payload(param.aead).as_mut_ptr(),
                &mut out_len,
                param.payload.decrypting_payload(param.aead).as_ptr(),
                param.payload.decrypting_payload(param.aead).len() as i32,
            )
        }.ok(RlsError::CipherDecryptError)?;
        unsafe {
            EVP_DecryptFinal_ex(
                self.ctx.as_mut_ptr(),
                param.payload.decrypting_payload(param.aead).as_mut_ptr().add(out_len as usize),
                &mut final_len,
            )
        }.ok(RlsError::CipherDecryptError)?;
        Ok((out_len + final_len) as usize)
    }
}

#[cfg(all(test, feature = "tls"))]
mod tests {
    use crate::boring::CryptParam;
    use crate::extend::Aead;
    use crate::record::RecordBuffer;
    use crate::{base64, rand, Cipher};
    use crate::boring::evp::CipherCrypto;

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
        let mut record_buffer = RecordBuffer::from_buffer(&aead, &mut buffer);
        record_buffer.add_explicit_iv(&iv);
        record_buffer.set_payload(&[1, 2, 3, 4, 5, 61, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2, 3, 4, 5, 67, 8, ]);
        println!("{:?}", &record_buffer.payload.value[..50]);

        let crypto = CipherCrypto::new(&aead, key).unwrap();
        let encrypted = crypto.encrypt(CryptParam {
            aead: record_buffer.aead,
            nonce: &[0; 12],
            iv: &iv,
            aad: &[0; 13],
            payload: &mut record_buffer.payload,
        }).unwrap();
        println!("{:?}", &buffer[..encrypted + 10]);
        let mut record_buffer = RecordBuffer::from_buffer(&aead, &mut buffer[..encrypted + 5]);
        // let decrypted = cryptor.decrypt(&encrypted, &key).unwrap();
        // println!("{:?}", decrypted);
        let len = crypto.decrypt(CryptParam {
            aead: &aead,
            nonce: &[0; 12],
            iv: &iv,
            aad: &[0; 13],
            payload: &mut record_buffer.payload,
        }).unwrap();
        println!("{:?}", &buffer[..len + 30]);
    }
}