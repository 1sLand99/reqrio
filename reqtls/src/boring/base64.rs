use crate::boring::bindings::*;
use crate::boring::ffi::CPointer;
use crate::error::RlsResult;

pub struct Base64 {
    ctx: CPointer<EVP_ENCODE_CTX>,
}

impl Base64 {
    fn new() -> Base64 {
        let ctx = CPointer::new(unsafe { EVP_ENCODE_CTX_new() });
        Base64 { ctx }
    }

    fn encrypt(&self, data: &[u8]) -> RlsResult<String> {
        let mut out = vec![0u8; data.len() * 2];
        let mut len = 0;
        unsafe {
            EVP_EncodeUpdate(
                self.ctx.as_mut_ptr(),
                out.as_mut_ptr(),
                &mut len,
                data.as_ptr(),
                data.len(),
            );
        }
        let mut padding = 0;
        unsafe {
            EVP_EncodeFinal(
                self.ctx.as_mut_ptr(),
                out.as_mut_ptr().add(len as usize),
                &mut padding,
            );
        }
        out.truncate((len + padding) as usize);
        Ok(String::from_utf8(out)?.replace("\n", ""))
    }

    fn decrypt(&self, data: &[u8]) -> RlsResult<Vec<u8>> {
        let mut out = vec![0u8; 3 * data.len() / 4];
        let mut len = 0;
        unsafe {
            EVP_DecodeUpdate(
                self.ctx.as_mut_ptr(),
                out.as_mut_ptr(),
                &mut len,
                data.as_ptr(),
                data.len(),
            );
        }
        let mut padding = 0;
        unsafe {
            EVP_DecodeFinal(
                self.ctx.as_mut_ptr(),
                out.as_mut_ptr().add(len as usize),
                &mut padding,
            );
        }
        out.truncate((len + padding) as usize);
        Ok(out)
    }
}


pub fn b64encode(context: impl AsRef<[u8]>) -> RlsResult<String> {
    Base64::new().encrypt(context.as_ref())
}

pub fn b64decode(context: impl AsRef<[u8]>) -> RlsResult<Vec<u8>> {
    Base64::new().decrypt(context.as_ref())
}