use std::ptr::null_mut;
use crate::boring::BoringResExt;
use super::Sha;
use crate::error::RlsResult;
use crate::ffi::CPointer;
use crate::RlsError;
use super::super::bindings::*;

pub struct Hasher {
    ctx: CPointer<EVP_MD_CTX>,
    sha: Sha,
    buf: [u8; 64],
    len: u32,
    updated: bool,
}

impl Hasher {
    pub fn new(sha: Sha) -> RlsResult<Hasher> {
        let ctx = CPointer::new_checked(unsafe { EVP_MD_CTX_new() }, RlsError::InitEvpCtxError)?;
        unsafe { EVP_DigestInit_ex(ctx.as_mut_ptr(), sha.evp_md(), null_mut()) }.ok(RlsError::InitDigestError)?;
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
        unsafe { EVP_DigestUpdate(self.ctx.as_mut_ptr(), buf.as_ref().as_ptr() as *const _, buf.as_ref().len()) }.ok(RlsError::DigestUpdateError)?;
        Ok(())
    }

    pub fn current_hash(&mut self) -> RlsResult<&[u8]> {
        if self.updated {
            let tmp_ctx = CPointer::new(unsafe { EVP_MD_CTX_new() });
            unsafe { EVP_MD_CTX_copy_ex(tmp_ctx.as_mut_ptr(), self.ctx.as_ptr()) };
            unsafe { EVP_DigestFinal_ex(tmp_ctx.as_mut_ptr(), self.buf.as_mut_ptr(), &mut self.len) }.ok(RlsError::DigestFinalError)?;
        };
        Ok(self.buf[..self.len as usize].as_ref())
    }


    pub fn finalize(mut self) -> RlsResult<Vec<u8>> {
        unsafe { EVP_DigestFinal_ex(self.ctx.as_mut_ptr(), self.buf.as_mut_ptr(), &mut self.len) }.ok(RlsError::DigestFinalError)?;
        Ok(self.buf[..self.len as usize].to_vec())
    }

    pub fn sha(&self) -> &Sha {
        &self.sha
    }
}

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