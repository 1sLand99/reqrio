use crate::boring::{BoringResExt, CryptDecodeParam, CryptEncodeParam};
use crate::error::RlsResult;
use crate::extend::Aead;
use crate::{ffi, RlsError};
use std::os::raw::{c_int, c_void};
use std::ptr::null_mut;
use crate::boring::bindings::EVP_AEAD_DEFAULT_TAG_LENGTH;
use crate::buffer::CipherEncodeBuffer;
use crate::suite::iv::Iv;

#[repr(C)]
pub struct AeadCtx {
    aead: Aead,
    tag_len: c_int,
    seq: u64,
    ctx: *mut c_void,
    rsv: [u32; 32],
}
ffi::c_pointer_free!(AeadCtx, AEAD_CTX_free);
unsafe impl Sync for AeadCtx {}
unsafe impl Send for AeadCtx {}

unsafe extern "C" {
    fn AEAD_CTX_init(ctx: *mut AeadCtx, key: *const u8, key_len: usize) -> c_int;
    fn AEAD_CTX_free(ctx: *mut AeadCtx);
    fn AEAD_CTX_seal(
        ctx: *const AeadCtx,
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
        ctx: *const AeadCtx,
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

impl AeadCtx {
    pub fn new(aead: Aead) -> AeadCtx {
        AeadCtx {
            aead,
            tag_len: EVP_AEAD_DEFAULT_TAG_LENGTH,
            seq: 0,
            ctx: null_mut(),
            rsv: [0; 32],
        }
    }
    pub fn new_with_key(aead: Aead, key: &[u8], tag_len: c_int) -> RlsResult<AeadCtx> {
        let mut ctx = AeadCtx::new(aead);
        ctx.tag_len = tag_len;
        unsafe { AEAD_CTX_init(&mut ctx, key.as_ptr(), key.len()) }.ok(RlsError::AeadEncryptError)?;
        Ok(ctx)
    }

    pub(crate) fn seal2(&self, seq: Option<u64>, mut buffer: CipherEncodeBuffer, iv: &Iv) -> RlsResult<usize> {
        let seq_num = if let Some(seq) = seq { seq } else { self.seq };
        let aad = buffer.aad(seq_num);
        let nonce = iv.as_array(seq_num, None);
        let payload = buffer.payload();
        let mut out_len = 0;
        unsafe {
            AEAD_CTX_seal(
                self,
                payload.encoded_payload().as_mut_ptr(),
                &mut out_len,
                payload.encoded_payload().len(),
                nonce.as_ptr(),
                nonce.len(),
                payload.origin_payload().as_ptr(),
                payload.origin_payload().len(),
                aad.as_ptr(),
                aad.len(),
            )
        }.ok(RlsError::AeadEncryptError)?;
        buffer.set_encrypted_len(out_len);
        Ok(out_len)
    }

    pub(crate) fn seal(&self, param: CryptEncodeParam) -> RlsResult<()> {
        let mut out_len = 0;
        let payload = param.buffer.payload();
        unsafe {
            AEAD_CTX_seal(
                self,
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

    pub fn seal_bytes(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> RlsResult<Vec<u8>> {
        let mut output = vec![0u8; plaintext.len() + 16];
        let mut output_len = 0usize;
        unsafe {
            AEAD_CTX_seal(
                self,
                output.as_mut_ptr(),
                &mut output_len,
                output.len(),
                nonce.as_ptr(),
                nonce.len(),
                plaintext.as_ptr(),
                plaintext.len(),
                aad.as_ptr(),
                aad.len(),
            )
        }.ok(RlsError::AeadEncryptError)?;
        output.truncate(output_len);
        Ok(output)
    }

    pub(crate) fn open(&self, param: CryptDecodeParam) -> RlsResult<usize> {
        let mut out_len = 0usize;
        let ok = unsafe {
            AEAD_CTX_open(
                self,
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

    pub fn open_bytes(&self, nonce: &[u8], aad: &[u8], cipher_bytes: &[u8]) -> RlsResult<Vec<u8>> {
        let mut output = vec![0u8; cipher_bytes.len() - 16];
        let mut output_len = 0usize;
        unsafe {
            AEAD_CTX_open(
                self,
                output.as_mut_ptr(),
                &mut output_len,
                output.len(),
                nonce.as_ptr(),
                nonce.len(),
                cipher_bytes.as_ptr(),
                cipher_bytes.len(),
                aad.as_ptr(),
                aad.len(),
            )
        }.ok(RlsError::AeadEncryptError)?;
        output.truncate(output_len);
        Ok(output)
    }
}


#[cfg(test)]
mod aead_tests {
    use crate::boring::bindings::EVP_AEAD_DEFAULT_TAG_LENGTH;
    use crate::boring::{AeadCtx, CryptDecodeParam, CryptEncodeParam};
    use crate::buffer::{TlsDecodeBuffer, CipherEncodeBuffer};
    use crate::{CipherSuite, RecordType, Version, Writer};
    use std::{env, fs};

    fn test_aead(suite: &'static CipherSuite, key: &[u8], size: usize, en: &[u8]) {
        let aead = suite.aead().unwrap();
        let ctx = AeadCtx::new_with_key(aead, key, EVP_AEAD_DEFAULT_TAG_LENGTH).unwrap();
        let payload = [1, 2, 3, 4, 5, 61, 2, 3, 4, 5, 6, 7, 8, 9, 23, 23];
        let iv = [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4];
        let mut buffer = [0; 1024];
        let mut record_buffer = CipherEncodeBuffer::new_tls(RecordType::HandShake, &mut buffer, &payload, suite);
        record_buffer.add_explicit_iv(&iv);
        let aad = record_buffer.aad(0);
        ctx.seal(CryptEncodeParam {
            nonce: &[0; 12],
            iv: &iv,
            aad: &aad,
            seq: &0,
            buffer: &mut record_buffer,
        }).unwrap();
        let len = record_buffer.record_len();
        assert_eq!(len, size);
        assert_eq!(&buffer[..len], en);
        let mut decoded_buffer = vec![0; 1024];
        let mut record_buffer = TlsDecodeBuffer::from_buffer(&buffer[..len], &mut decoded_buffer, suite).unwrap();
        let aad = record_buffer.aad(0).unwrap();
        let mut len = ctx.open(CryptDecodeParam {
            nonce: &[0; 12],
            iv: &iv,
            aad: &aad,
            seq: &0,
            buffer: &mut record_buffer,
        }).unwrap();
        if let &Version::TLS_1_3 = suite.version {
            len -= 1;
        }
        assert_eq!(len, 16);
        assert_eq!(&decoded_buffer[..len], payload);
    }

    #[test]
    fn test_aead_ctx() {
        let token = fs::read_to_string("../TOKEN").unwrap_or_else(|_| {
            env::var("REQRIO_TOKEN").unwrap_or("".to_string())
        });
        Writer::check_subscription(token).unwrap();
        let key = [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        test_aead(&CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, &key, 45, &[22, 3, 3, 0, 40, 5, 6, 7, 8, 1, 2, 3, 4, 73, 124, 57, 79, 141, 133, 227, 18, 144, 234, 121, 155, 242, 80, 24, 135, 186, 135, 31, 85, 210, 190, 133, 14, 120, 110, 158, 242, 184, 89, 14, 110]);
        let key = [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        test_aead(&CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, &key, 45, &[22, 3, 3, 0, 40, 5, 6, 7, 8, 1, 2, 3, 4, 212, 216, 11, 46, 55, 11, 51, 6, 9, 103, 221, 215, 100, 98, 203, 62, 17, 75, 66, 161, 168, 255, 72, 59, 189, 213, 196, 182, 248, 164, 109, 233]);
        test_aead(&CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, &key, 37, &[22, 3, 3, 0, 32, 117, 245, 41, 12, 78, 148, 113, 238, 9, 193, 134, 57, 89, 54, 164, 34, 16, 30, 205, 190, 166, 146, 81, 111, 237, 224, 212, 24, 176, 182, 162, 76]);

        let key = [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        test_aead(&CipherSuite::TLS_AES_128_GCM_SHA256, &key, 38, &[23, 3, 3, 0, 33, 73, 124, 57, 79, 141, 133, 227, 18, 144, 234, 121, 155, 242, 80, 24, 135, 242, 85, 24, 178, 65, 169, 220, 3, 194, 146, 52, 174, 244, 106, 123, 230, 31]);
        test_aead(&CipherSuite::TLS_SM4_GCM_SM3, &key, 38, &[23, 3, 3, 0, 33, 230, 37, 165, 245, 42, 213, 2, 105, 130, 26, 88, 111, 64, 103, 112, 27, 4, 49, 122, 222, 51, 209, 20, 222, 149, 172, 18, 163, 84, 66, 244, 154, 211]);

        let key = [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        test_aead(&CipherSuite::TLS_AES_256_GCM_SHA384, &key, 38, &[23, 3, 3, 0, 33, 212, 216, 11, 46, 55, 11, 51, 6, 9, 103, 221, 215, 100, 98, 203, 62, 129, 117, 41, 52, 75, 226, 135, 56, 115, 180, 125, 134, 114, 206, 161, 50, 134]);
        test_aead(&CipherSuite::TLS_CHACHA20_POLY1305_SHA256, &key, 38, &[23, 3, 3, 0, 33, 117, 245, 41, 12, 78, 148, 113, 238, 9, 193, 134, 57, 89, 54, 164, 34, 117, 170, 210, 251, 96, 6, 14, 229, 70, 1, 117, 118, 12, 51, 77, 24, 208]);
    }
}