use crate::error::RlsResult;
use crate::extend::Aead;
use crate::rand;
use boring_sys::{CRYPTO_memcmp, EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_new, EVP_DecryptFinal_ex, EVP_DecryptInit_ex, EVP_DecryptUpdate, EVP_EncryptFinal_ex, EVP_EncryptInit_ex, EVP_EncryptUpdate, EVP_aes_128_cbc, EVP_aes_256_cbc, EVP_sha1, EVP_CIPHER, EVP_CIPHER_CTX, HMAC};
use std::ptr;
use std::ptr::null_mut;

pub struct CipherCryptor {
    ctx: *mut EVP_CIPHER_CTX,
    mac_key: [u8; 20],
    evp_cipher: *const EVP_CIPHER,
}

impl CipherCryptor {
    pub fn new(aead: &Aead) -> RlsResult<CipherCryptor> {
        let evp_cipher = match aead {
            Aead::AES_128_CBC_SHA => unsafe { EVP_aes_128_cbc() }
            Aead::AES_256_CBC_SHA => unsafe { EVP_aes_256_cbc() }
            _ => return Err("not cipher,but in cipher".into())
        };
        println!("{}", evp_cipher.is_null());
        // assert_eq!(key.len(), 36);
        let ctx = unsafe { EVP_CIPHER_CTX_new() };

        // let ok = unsafe { EVP_EncryptInit(ctx, evp_aead, key.as_ptr(), null()) };
        // // 初始化失败，ok是空
        // unsafe {
        //     if ok != 1 {
        //         let err = ERR_get_error();
        //         println!("BoringSSL Error: {:x}", err); // 打印出十六进制错误码
        //         return Err(RlsError::AeadCryptError);
        //     }
        // }
        Ok(CipherCryptor { ctx, mac_key: rand::random(), evp_cipher })
    }

    /// cbc加密块:
    /// ```text
    /// mac = HMAC_SHA1(mac_key, seq_num + hdr + plaintext) //20位
    /// ciphertext = AES_CBC(key, iv, plaintext || mac || padding) //pcsk7
    ///```
    pub fn encrypt(&self, plaintext: &[u8], key: &[u8], iv: &[u8; 16]) -> RlsResult<Vec<u8>> {
        unsafe {
            // 1. 初始化加密操作，传入本次使用的 IV
            if EVP_EncryptInit_ex(
                self.ctx,
                self.evp_cipher, // 使用 new 中已经设定的算法
                null_mut(),
                key.as_ptr(), // 使用 new 中已经设定的 key
                iv.as_ptr(),
            ) != 1 {
                return Err("Failed to init encryption with IV".into());
            }

            // 2. 准备缓冲区
            // CBC 模式输出长度最多为 plaintext.len() + block_size
            let block_size = 16;
            let mut ciphertext = vec![0u8; plaintext.len() + block_size];
            let mut out_len = 0i32;
            let mut final_len = 0i32;

            // 3. 执行加密
            if EVP_EncryptUpdate(
                self.ctx,
                ciphertext.as_mut_ptr(),
                &mut out_len,
                plaintext.as_ptr(),
                plaintext.len() as i32,
            ) != 1 {
                return Err("Encryption update failed".into());
            }

            // 4. 完成加密（处理 Padding）
            if EVP_EncryptFinal_ex(
                self.ctx,
                ciphertext.as_mut_ptr().add(out_len as usize),
                &mut final_len,
            ) != 1 {
                return Err("Encryption final failed".into());
            }

            // 截断到实际加密后的长度
            ciphertext.truncate((out_len + final_len) as usize);

            // 5. 计算 HMAC-SHA1 (针对 IV + Ciphertext)
            // 很多协议要求把 IV 也放入认证范围，以防止 IV 被篡改
            let mut auth_data = Vec::with_capacity(iv.len() + ciphertext.len());
            auth_data.extend_from_slice(iv);
            auth_data.extend_from_slice(&ciphertext);

            let mut mac = [0u8; 20]; // SHA1 长度为 20 字节
            let mut mac_len = 20u32;

            if HMAC(
                EVP_sha1(),
                self.mac_key.as_ptr() as *const _,
                self.mac_key.len(),
                auth_data.as_ptr(),
                auth_data.len(),
                mac.as_mut_ptr(),
                &mut mac_len,
            ).is_null() {
                return Err("HMAC calculation failed".into());
            }

            // 6. 最终结果：IV + Ciphertext + MAC
            let mut result = auth_data; // 此时 auth_data 已经是 IV + Ciphertext
            result.extend_from_slice(&mac);
            println!("{:?}", result);
            Ok(result)
        }
    }

    pub fn decrypt(&self, input: &[u8], key: &[u8]) -> RlsResult<Vec<u8>> {
        // 1. 基础长度校验
        // 最小长度 = 16 (IV) + 0 (数据) + 20 (MAC) + 至少一个 block 的 padding
        if input.len() < (16 + 20) {
            return Err("Input data too short".into());
        }

        let iv_len = 16;
        let mac_len = 20;
        let data_with_iv_len = input.len() - mac_len;

        // 拆分数据
        let iv_and_ciphertext = &input[0..data_with_iv_len];
        let expected_mac = &input[data_with_iv_len..];
        let iv = &input[0..iv_len];
        let ciphertext = &input[iv_len..data_with_iv_len];

        unsafe {
            // 2. 校验 HMAC (必须先于解密)
            let mut computed_mac = [0u8; 20];
            let mut computed_mac_len = 20u32;

            if HMAC(
                EVP_sha1(),
                self.mac_key.as_ptr() as *const _,
                self.mac_key.len(),
                iv_and_ciphertext.as_ptr(),
                iv_and_ciphertext.len(),
                computed_mac.as_mut_ptr(),
                &mut computed_mac_len,
            ).is_null() {
                return Err("HMAC calculation failed".into());
            }

            // 使用恒定时间比较 (Constant-time comparison) 防止侧信道攻击
            if CRYPTO_memcmp(
                computed_mac.as_ptr() as *const _,
                expected_mac.as_ptr() as *const _,
                mac_len,
            ) != 0 {
                return Err("HMAC verification failed".into());
            }

            // 3. 初始化解密
            // let ctx = self.encrypt_ctx; // 实际开发中建议加密解密使用独立的 ctx
            if EVP_DecryptInit_ex(
                self.ctx,
                self.evp_cipher, // 使用之前设定的算法
                ptr::null_mut(),
                key.as_ptr(), // 使用之前设定的 key
                iv.as_ptr(),
            ) != 1 {
                return Err("Failed to init decryption".into());
            }

            // 4. 执行解密
            let mut plaintext = vec![0u8; ciphertext.len()];
            let mut out_len = 0i32;
            let mut final_len = 0i32;

            if EVP_DecryptUpdate(
                self.ctx,
                plaintext.as_mut_ptr(),
                &mut out_len,
                ciphertext.as_ptr(),
                ciphertext.len() as i32,
            ) != 1 {
                return Err("Decryption update failed".into());
            }

            // 5. 完成解密并移除 Padding
            // 如果 Padding 不正确，这里会报错，但因为我们先校验了 HMAC，这通常意味着数据被破坏
            if EVP_DecryptFinal_ex(
                self.ctx,
                plaintext.as_mut_ptr().add(out_len as usize),
                &mut final_len,
            ) != 1 {
                return Err("Decryption final failed (possible padding error)".into());
            }

            plaintext.truncate((out_len + final_len) as usize);
            Ok(plaintext)
        }
    }
}

impl Drop for CipherCryptor {
    fn drop(&mut self) {
        unsafe { EVP_CIPHER_CTX_free(self.ctx); }
    }
}

#[cfg(test)]
mod tests {
    use crate::boring::cipher::CipherCryptor;
    use crate::extend::Aead;
    use crate::rand;

    #[test]
    fn test_cipher_cryptor() {
        let aead = Aead::AES_128_CBC_SHA;
        let key = rand::random::<[u8; 16]>();
        let iv = rand::random::<[u8; 16]>();
        let mut payload = vec![1, 2, 3, 4, 5, 6, 1, 2, 3, 4, 5, 6];
        // payload.extend(&[0; 20]);
        // let mut payload = Payload::from_slice(&mut payload);
        let cryptor = CipherCryptor::new(&aead).unwrap();
        let encrypted = cryptor.encrypt(&payload, &key, &iv).unwrap();
        let decrypted = cryptor.decrypt(&encrypted, &key).unwrap();
        println!("{:?}", decrypted);
        // cryptor.encrypt(CryptParam {
        //     aead: &aead,
        //     nonce: &[0; 12],
        //     iv: &iv,
        //     aad: &[0; 13],
        //     payload: &mut payload,
        // }).unwrap();
        // println!("{:?}", &payload[0..]);
    }
}