use std::ptr::null_mut;
use super::Sha;
use super::super::bindings::*;
use crate::error::RlsResult;
use crate::RlsError;


pub struct Hmac {
    ctx: *mut HMAC_CTX,
    buf: [u8; 64],
    len: u32,
}

impl Hmac {
    pub fn new(key: impl AsRef<[u8]>, sha: Sha) -> RlsResult<Hmac> {
        let ctx = unsafe { HMAC_CTX_new() };
        if ctx.is_null() { return Err(RlsError::HmacCtxNull); }
        let ret = unsafe {
            HMAC_Init_ex(
                ctx,
                key.as_ref().as_ptr() as *const _,
                key.as_ref().len(),
                sha.evp_md(),
                null_mut(),
            )
        };
        if ret != 1 {
            unsafe { HMAC_CTX_free(ctx); }
            return Err(RlsError::HmacInitError);
        }
        Ok(Hmac {
            ctx,
            buf: [0; 64],
            len: 0,
        })
    }

    pub fn update(&self, data: impl AsRef<[u8]>) -> RlsResult<()> {
        let ret = unsafe { HMAC_Update(self.ctx, data.as_ref().as_ptr(), data.as_ref().len()) };
        if ret != 1 { return Err(RlsError::HmacUpdateError); }
        Ok(())
    }

    pub fn finalize(&mut self) -> RlsResult<&[u8]> {
        let ret = unsafe { HMAC_Final(self.ctx, self.buf.as_mut_ptr(), &mut self.len) };
        if ret != 1 { return Err(RlsError::HmacFinalizeError); }
        Ok(&self.buf[..self.len as usize])
    }
}

impl Drop for Hmac {
    fn drop(&mut self) {
        unsafe { HMAC_CTX_free(self.ctx); }
    }
}

#[cfg(test)]
mod tests {
    use crate::boring::hash::{Hmac, Sha};

    #[test]
    fn test_hmac() {
        let mut hmac = Hmac::new("test", Sha::Sha256).unwrap();
        hmac.update("sdf").unwrap();
        println!("{:?}", hmac.finalize().unwrap());
    }
}