use std::string::FromUtf8Error;
use crate::boring::bindings::*;
use crate::boring::BoringResExt;
use crate::error::RlsResult;
use crate::ffi::CPointer;
use crate::RlsError;

pub struct Base64 {
    ctx: CPointer<EVP_ENCODE_CTX>,
}

impl Base64 {
    pub fn new() -> Base64 {
        let ctx = CPointer::new(unsafe { EVP_ENCODE_CTX_new() });
        Base64 { ctx }
    }

    pub fn encode(&self, data: &[u8]) -> Vec<u8> {
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
        out.into_iter().filter(|x| *x != b'\n').collect()
    }

    pub fn decode(&self, data: &[u8]) -> RlsResult<Vec<u8>> {
        let mut out = vec![0u8; 3 * data.len() / 4];
        let mut len = 0;
        let ret = unsafe {
            EVP_DecodeUpdate(
                self.ctx.as_mut_ptr(),
                out.as_mut_ptr(),
                &mut len,
                data.as_ptr(),
                data.len(),
            )
        };
        if ret == -1 { return Err(RlsError::Currently("b64 decode update fail".to_owned())); };
        println!("{}", ret);
        let mut padding = 0;
        unsafe {
            EVP_DecodeFinal(
                self.ctx.as_mut_ptr(),
                out.as_mut_ptr().add(len as usize),
                &mut padding,
            )
        }.ok(RlsError::Currently("b64 decode final fail".to_owned()))?;
        out.truncate((len + padding) as usize);
        Ok(out)
    }
}


pub fn b64encode(context: impl AsRef<[u8]>) -> Result<String, FromUtf8Error> {
    let bs = Base64::new().encode(context.as_ref());
    String::from_utf8(bs)
}

pub fn b64decode(context: impl AsRef<[u8]>) -> RlsResult<Vec<u8>> {
    Base64::new().decode(context.as_ref())
}