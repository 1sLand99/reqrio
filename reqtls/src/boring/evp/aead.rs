use crate::boring::{BoringResExt, CryptDecodeParam, CryptEncodeParam};
use crate::error::RlsResult;
use crate::extend::Aead;
use crate::ffi::CPointer;
use crate::{ffi, RlsError};
use std::os::raw::c_int;

#[repr(C)]
#[allow(clippy::upper_case_acronyms)]
#[allow(non_camel_case_types)]
struct AEAD_CTX {
    _unused: [u8; 0],
}
ffi::c_pointer_free!(AEAD_CTX, AEAD_CTX_free);

unsafe extern "C" {
    fn AEAD_CTX_new(aead: Aead, key: *const u8, key_len: usize, tag_len: usize) -> *mut AEAD_CTX;
    fn AEAD_CTX_free(ctx: *mut AEAD_CTX);
    fn AEAD_CTX_seal(
        ctx: *const AEAD_CTX,
        out: *mut u8,
        out_len: *mut usize,
        max_out_len: usize,
        nonce: *const u8,
        nonce_len: usize,
        in_: *const u8,
        in_len: usize,
        aad: *const u8,
        aad_len: usize,
    ) -> c_int;

    fn AEAD_CTX_open(
        ctx: *const AEAD_CTX,
        out: *mut u8,
        out_len: *mut usize,
        max_out_len: usize,
        nonce: *const u8,
        nonce_len: usize,
        input: *const u8,
        in_len: usize,
        aad: *const u8,
        aad_len: usize,
    ) -> c_int;
}

pub struct AeadCtx(CPointer<AEAD_CTX>);

impl AeadCtx {
    pub fn new(aead: &Aead, key: &[u8], tag_len: i32) -> RlsResult<AeadCtx> {
        let ctx = unsafe { AEAD_CTX_new(*aead, key.as_ptr(), key.len(), tag_len as usize) };
        let ctx = CPointer::new_checked(ctx, RlsError::AeadCryptError)?;
        Ok(AeadCtx(ctx))
    }

    pub fn seal(&self, param: CryptEncodeParam) -> RlsResult<()> {
        let mut out_len = 0;
        let payload = param.buffer.payload();
        unsafe {
            AEAD_CTX_seal(
                self.0.as_ptr(),
                payload.encoded_payload().as_mut_ptr(),
                &mut out_len,
                payload.encoded_payload().len(),
                param.nonce.as_ptr(),
                param.nonce.len(),
                payload.origin_payload().as_ptr(),
                payload.origin_payload().len(),
                param.aad.as_ptr(),
                param.aad.len(),
            )
        }.ok(RlsError::AeadEncryptError)?;
        param.buffer.set_encrypted_len(out_len);
        Ok(())
    }

    pub fn open(&self, param: CryptDecodeParam) -> RlsResult<usize> {
        let mut out_len = 0usize;
        let ok = unsafe {
            AEAD_CTX_open(
                self.0.as_ptr(),
                param.buffer.decrypted_buffer().as_mut_ptr(),
                &mut out_len,
                param.buffer.decrypted_buffer().len() - 16,
                param.nonce.as_ptr(),
                param.nonce.len(),
                param.buffer.encrypted_payload().as_ptr(),
                param.buffer.encrypted_payload().len(),
                param.aad.as_ptr(),
                param.aad.len(),
            )
        };
        if ok != 1 { Err(RlsError::AeadDecryptError) } else { Ok(out_len) }
    }
}


#[cfg(test)]
mod aead_tests {
    use crate::boring::bindings::EVP_AEAD_DEFAULT_TAG_LENGTH;
    use crate::boring::{AeadCtx, CryptDecodeParam, CryptEncodeParam};
    use crate::buffer::{RecordDecodeBuffer, RecordEncodeBuffer};
    use crate::extend::Aead;
    use crate::{RecordType, Version};

    fn test_aead(aead: Aead, version: Version, key: &[u8], size: usize, en: &[u8]) {
        let ctx = AeadCtx::new(&aead, &key, EVP_AEAD_DEFAULT_TAG_LENGTH).unwrap();
        let payload = [1, 2, 3, 4, 5, 61, 2, 3, 4, 5, 6, 7, 8, 9, 23, 23];
        let iv = [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4];
        let mut buffer = [0; 1024];
        let mut record_buffer = RecordEncodeBuffer::new(RecordType::HandShake, &version, &mut buffer, &payload, &aead);
        record_buffer.add_explicit_iv(&iv);
        ctx.seal(CryptEncodeParam {
            nonce: &[0; 12],
            iv: &iv,
            aad: &[0; 13],
            seq: &0,
            buffer: &mut record_buffer,
        }).unwrap();
        let len = record_buffer.record_len();
        assert_eq!(len, size);
        assert_eq!(&buffer[..len], en);
        let mut decoded_buffer = vec![0; 1024];
        let mut record_buffer = RecordDecodeBuffer::from_buffer(&buffer[..len], &mut decoded_buffer, &aead, &version).unwrap();
        let mut len = ctx.open(CryptDecodeParam {
            nonce: &[0; 12],
            iv: &iv,
            aad: &[0; 13],
            seq: &0,
            buffer: &mut record_buffer,
        }).unwrap();
        if let Version::TLS_1_3 = version {
            len -= 1;
        }
        assert_eq!(len, 16);
        assert_eq!(&decoded_buffer[..len], payload);
    }

    #[test]
    fn test_aead_ctx() {
        let key = [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        test_aead(Aead::AES_128_GCM, Version::TLS_1_2, &key, 45, &[22, 3, 3, 0, 40, 5, 6, 7, 8, 1, 2, 3, 4, 73, 124, 57, 79, 141, 133, 227, 18, 144, 234, 121, 155, 242, 80, 24, 135, 115, 74, 77, 64, 156, 162, 158, 171, 2, 52, 55, 109, 63, 93, 199, 50]);
        let key = [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        test_aead(Aead::AES_256_GCM, Version::TLS_1_2, &key, 45, &[22, 3, 3, 0, 40, 5, 6, 7, 8, 1, 2, 3, 4, 212, 216, 11, 46, 55, 11, 51, 6, 9, 103, 221, 215, 100, 98, 203, 62, 168, 242, 215, 119, 68, 68, 4, 162, 38, 24, 17, 144, 168, 130, 198, 48]);
        test_aead(Aead::ChaCha20_POLY1305, Version::TLS_1_2, &key, 37, &[22, 3, 3, 0, 32, 117, 245, 41, 12, 78, 148, 113, 238, 9, 193, 134, 57, 89, 54, 164, 34, 136, 208, 109, 163, 83, 243, 63, 22, 105, 239, 120, 188, 187, 141, 84, 36]);

        let key = [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        test_aead(Aead::AES_128_GCM, Version::TLS_1_3, &key, 38, &[23, 3, 3, 0, 33, 73, 124, 57, 79, 141, 133, 227, 18, 144, 234, 121, 155, 242, 80, 24, 135, 242, 87, 229, 185, 108, 217, 141, 240, 171, 215, 134, 151, 75, 132, 240, 130, 211]);
        let key = [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        test_aead(Aead::AES_256_GCM, Version::TLS_1_3, &key, 38, &[23, 3, 3, 0, 33, 212, 216, 11, 46, 55, 11, 51, 6, 9, 103, 221, 215, 100, 98, 203, 62, 129, 72, 255, 221, 119, 237, 15, 46, 162, 122, 99, 249, 160, 15, 117, 52, 204]);
        test_aead(Aead::ChaCha20_POLY1305, Version::TLS_1_3, &key, 38, &[23, 3, 3, 0, 33, 117, 245, 41, 12, 78, 148, 113, 238, 9, 193, 134, 57, 89, 54, 164, 34, 117, 25, 107, 166, 190, 42, 147, 21, 68, 143, 23, 231, 169, 245, 221, 204, 121]);
    }
}


// pub struct AeadCrypto {
//     ctx: AeadCtx,
// }
//
// impl AeadCrypto {
//     pub fn new(aead: Aead, key: &[u8]) -> RlsResult<AeadCrypto> {
//         let ctx = AeadCtx::new(aead, key, EVP_AEAD_DEFAULT_TAG_LENGTH as usize)?;
//         // let evp_aead = match aead {
//         //     Aead::AES_128_GCM => unsafe { EVP_aead_aes_128_gcm() },
//         //     Aead::AES_256_GCM => unsafe { EVP_aead_aes_256_gcm() }
//         //     Aead::ChaCha20_POLY1305 => unsafe { EVP_aead_chacha20_poly1305() }
//         //     _ => return Err("not aead,but in aead".into())
//         // };
//         // let mut ctx = MaybeUninit::zeroed();
//         // let ok = unsafe { EVP_AEAD_CTX_init(ctx.as_mut_ptr(), evp_aead, key.as_ptr(), key.len(), EVP_AEAD_DEFAULT_TAG_LENGTH as usize, null_mut()) };
//         // if ok != 1 { return Err(RlsError::AeadCryptError); }
//         Ok(AeadCrypto { ctx })
//     }
//
//     pub fn encrypt(&self, param: CryptEncodeParam) -> RlsResult<()> {
//         let mut out_len = 0;
//         let payload = param.buffer.payload();
//         unsafe {
//             EVP_AEAD_CTX_seal(
//                 self.ctx.as_ptr(),
//                 payload.encoded_payload().as_mut_ptr(),
//                 &mut out_len,
//                 payload.encoded_payload().len(),
//                 param.nonce.as_ptr(),
//                 param.nonce.len(),
//                 payload.origin_payload().as_ptr(),
//                 payload.origin_payload().len(),
//                 param.aad.as_ptr(),
//                 param.aad.len(),
//             )
//         }.ok(RlsError::AeadEncryptError)?;
//         param.buffer.set_encrypted_len(out_len);
//         Ok(())
//     }
//
//     pub fn decrypt(&self, param: CryptDecodeParam) -> RlsResult<usize> {
//         let mut out_len = 0usize;
//         let ok = unsafe {
//             EVP_AEAD_CTX_open(
//                 self.ctx.as_ptr(),
//                 param.buffer.decrypted_buffer().as_mut_ptr(),
//                 &mut out_len,
//                 param.buffer.decrypted_buffer().len() - 16,
//                 param.nonce.as_ptr(),
//                 param.nonce.len(),
//                 param.buffer.encrypted_payload().as_ptr(),
//                 param.buffer.encrypted_payload().len(),
//                 param.aad.as_ptr(),
//                 param.aad.len(),
//             )
//         };
//         if ok != 1 { Err(RlsError::AeadDecryptError) } else { Ok(out_len) }
//     }
// }
//
// impl Drop for AeadCrypto {
//     fn drop(&mut self) {
//         unsafe { EVP_AEAD_CTX_cleanup(self.ctx.as_mut_ptr()) }
//     }
// }
//
// unsafe impl Send for AeadCrypto {}
//
// unsafe impl Sync for AeadCrypto {}