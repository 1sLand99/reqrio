use std::ffi::c_int;
use crate::boring::CryptParam;
use crate::error::RlsResult;
use crate::extend::Aead;
use crate::{rand, RlsError};
use super::bindings::*;
use std::ptr::null_mut;
use crate::hash::hmac;

trait BoringResExt {
    fn ok(self, error: RlsError) -> RlsResult<()>;
}

impl BoringResExt for c_int {
    fn ok(self, error: RlsError) -> RlsResult<()> {
        if self != 1 { return Err(error); }
        Ok(())
    }
}

pub struct CipherCryptor {
    ctx: *mut EVP_CIPHER_CTX,
    mac_key: [u8; 20],
    key: Vec<u8>,
    evp_cipher: *const EVP_CIPHER,
}

impl CipherCryptor {
    pub fn new(aead: &Aead, key: Vec<u8>) -> RlsResult<CipherCryptor> {
        let evp_cipher = match aead {
            Aead::AES_128_CBC_SHA => unsafe { EVP_aes_128_cbc() }
            Aead::AES_256_CBC_SHA => unsafe { EVP_aes_256_cbc() }
            _ => return Err("not cipher,but in cipher".into())
        };
        let ctx = unsafe { EVP_CIPHER_CTX_new() };
        Ok(CipherCryptor {
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
        unsafe { EVP_EncryptInit_ex(self.ctx, self.evp_cipher, null_mut(), self.key.as_ptr(), param.iv.as_ptr()) }.ok(RlsError::CipherCryptError)?;
        let mut out_len = 0;
        unsafe {
            EVP_EncryptUpdate(
                self.ctx,
                param.payload.encrypting_out(param.aead).as_mut_ptr(),
                &mut out_len,
                param.payload.encrypting_in(param.aead).as_ptr(),
                param.payload.len as i32)
        }.ok(RlsError::CipherEncryptError)?;
        let mut final_len = 0;
        unsafe {
            EVP_EncryptFinal_ex(
                self.ctx,
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
        unsafe { EVP_DecryptInit_ex(self.ctx, self.evp_cipher, null_mut(), self.key.as_ptr(), param.iv.as_ptr()) }.ok(RlsError::CipherCryptError)?;

        // 4. 执行解密
        let mut out_len = 0i32;
        let mut final_len = 0i32;
        unsafe {
            EVP_DecryptUpdate(
                self.ctx,
                param.payload.decrypting_payload(param.aead).as_mut_ptr(),
                &mut out_len,
                param.payload.decrypting_payload(param.aead).as_ptr(),
                param.payload.decrypting_payload(param.aead).len() as i32,
            )
        }.ok(RlsError::CipherDecryptError)?;
        unsafe {
            EVP_DecryptFinal_ex(
                self.ctx,
                param.payload.decrypting_payload(param.aead).as_mut_ptr().add(out_len as usize),
                &mut final_len,
            )
        }.ok(RlsError::CipherDecryptError)?;
        Ok((out_len + final_len) as usize)
    }
}

impl Drop for CipherCryptor {
    fn drop(&mut self) {
        unsafe { EVP_CIPHER_CTX_free(self.ctx); }
    }
}

unsafe impl Send for CipherCryptor {}

#[cfg(test)]
mod tests {
    use crate::boring::cipher::CipherCryptor;
    use crate::boring::CryptParam;
    use crate::extend::Aead;
    use crate::rand;
    use crate::record::RecordBuffer;

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

        let cryptor = CipherCryptor::new(&aead, key).unwrap();
        let encrypted = cryptor.encrypt(CryptParam {
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
        let len = cryptor.decrypt(CryptParam {
            aead: &aead,
            nonce: &[0; 12],
            iv: &iv,
            aad: &[0; 13],
            payload: &mut record_buffer.payload,
        }).unwrap();
        println!("{:?}", &buffer[..len + 30]);
    }
}