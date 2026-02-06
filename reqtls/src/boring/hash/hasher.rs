use std::ptr::null_mut;
use super::Sha;
use crate::error::RlsResult;
use crate::RlsError;
use super::super::bindings::*;

pub struct Hasher {
    ctx: *mut EVP_MD_CTX,
    sha: Sha,
    buf: [u8; 64],
    len: u32,
    updated: bool,
}

impl Hasher {
    pub fn new(sha: Sha) -> RlsResult<Hasher> {
        let ctx = unsafe { EVP_MD_CTX_new() };
        if ctx.is_null() { return Err(RlsError::InitEvpCtxError); };
        let ret = unsafe { EVP_DigestInit_ex(ctx, sha.evp_md(), null_mut()) };
        if ret != 1 {
            unsafe { EVP_MD_CTX_free(ctx); }
            return Err(RlsError::InitDigestError);
        }
        Ok(Hasher {
            ctx,
            sha,
            buf: [0; 64],
            len: 0,
            updated: false,
        })
    }


    pub fn update(&mut self, buf: impl AsRef<[u8]>) -> RlsResult<()> {
        self.updated = true;
        let ret = unsafe { EVP_DigestUpdate(self.ctx, buf.as_ref().as_ptr() as *const _, buf.as_ref().len()) };
        if ret != 1 { return Err(RlsError::DigestUpdateError); };
        Ok(())
    }

    pub fn current_hash(&mut self) -> RlsResult<&[u8]> {
        if self.updated {
            let tmp_ctx = unsafe { EVP_MD_CTX_new() };
            unsafe { EVP_MD_CTX_copy_ex(tmp_ctx, self.ctx) };
            let ret = unsafe { EVP_DigestFinal_ex(tmp_ctx, self.buf.as_mut_ptr(), &mut self.len) };
            unsafe { EVP_MD_CTX_free(tmp_ctx) }
            if ret != 1 { return Err(RlsError::DigestFinalError); };
        };
        Ok(self.buf[..self.len as usize].as_ref())
    }


    pub fn finalize(mut self) -> RlsResult<Vec<u8>> {
        let ret = unsafe { EVP_DigestFinal_ex(self.ctx, self.buf.as_mut_ptr(), &mut self.len) };
        if ret != 1 { return Err(RlsError::DigestFinalError); };
        Ok(self.buf[..self.len as usize].to_vec())
    }

    pub fn sha(&self) -> &Sha {
        &self.sha
    }
}


impl Drop for Hasher {
    fn drop(&mut self) {
        unsafe { EVP_MD_CTX_free(self.ctx) }
    }
}

unsafe impl Send for Hasher {}

#[cfg(test)]
mod tests {
    use crate::boring::Sha;
    use crate::boring::hash::hasher::Hasher;

    #[test]
    fn test_hasher() {
        let mut hasher = Hasher::new(Sha::Sha256).unwrap();
        hasher.update(b"hello world").unwrap();
        println!("{:?}", hasher.finalize().unwrap());
        println!("{:?}", super::super::sha256("hello world").unwrap());

        let mut hash_md5 = Hasher::new(Sha::MD5).unwrap();
        hash_md5.update(b"hello world").unwrap();
        println!("{:?}", hash_md5.finalize().unwrap());

        println!("{:?}", super::super::md5("hello world").unwrap());
    }
}