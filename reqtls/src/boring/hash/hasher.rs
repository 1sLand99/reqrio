use super::super::bindings::*;
use super::error::HashError;
use super::HashType;
use crate::boring::BoringResExt;
use crate::ffi::CPointer;
use std::ptr::null_mut;

pub struct Hasher {
    ctx: CPointer<EVP_MD_CTX>,
    hash_type: HashType,
    buf: [u8; 64],
    len: u32,
    updated: bool,
}

impl Default for Hasher {
    fn default() -> Self {
        Hasher {
            ctx: CPointer::nullptr(),
            hash_type: HashType::Sha256,
            buf: [0; 64],
            len: 0,
            updated: false,
        }
    }
}

impl Hasher {
    pub fn new(sha: HashType) -> Result<Hasher, HashError> {
        let mut hasher = Hasher::default();
        hasher.init(sha)?;
        Ok(hasher)
    }

    pub(crate) fn init(&mut self, sha: HashType) -> Result<(), HashError> {
        let ctx = CPointer::new_checked(unsafe { EVP_MD_CTX_new() }, HashError::InitEvpCtxError)?;
        unsafe { EVP_DigestInit_ex(ctx.as_mut_ptr(), sha.evp_md(), null_mut()) }.ok(HashError::InitDigestError)?;
        self.ctx = ctx;
        self.hash_type = sha;
        Ok(())
    }


    pub fn update(&mut self, buf: impl AsRef<[u8]>) -> Result<(), HashError> {
        if self.ctx.is_null() { return Err(HashError::MustInitFirst) }
        self.updated = true;
        unsafe { EVP_DigestUpdate(self.ctx.as_mut_ptr(), buf.as_ref().as_ptr() as *const _, buf.as_ref().len()) }.ok(HashError::DigestUpdateError)?;
        Ok(())
    }

    pub fn current_hash(&mut self) -> Result<&[u8], HashError> {
        if self.ctx.is_null() { return Err(HashError::MustInitFirst) }
        if self.updated {
            self.updated = false;
            let tmp_ctx = CPointer::new(unsafe { EVP_MD_CTX_new() });
            unsafe { EVP_MD_CTX_copy_ex(tmp_ctx.as_mut_ptr(), self.ctx.as_ptr()) };
            unsafe { EVP_DigestFinal_ex(tmp_ctx.as_mut_ptr(), self.buf.as_mut_ptr(), &mut self.len) }.ok(HashError::DigestFinalError)?;
        };
        Ok(self.buf[..self.len as usize].as_ref())
    }


    pub fn finalize(mut self) -> Result<Vec<u8>, HashError> {
        if self.ctx.is_null() { return Err(HashError::MustInitFirst) }
        unsafe { EVP_DigestFinal_ex(self.ctx.as_mut_ptr(), self.buf.as_mut_ptr(), &mut self.len) }.ok(HashError::DigestFinalError)?;
        Ok(self.buf[..self.len as usize].to_vec())
    }

    pub fn hash_type(&self) -> &HashType {
        &self.hash_type
    }

    pub fn inited(&self) -> bool {
        !self.ctx.is_null()
    }
}

#[cfg(test)]
mod tests {
    use crate::boring::hash::hasher::Hasher;
    use crate::boring::HashType;

    #[test]
    fn test_hasher() {
        let mut hasher = Hasher::new(HashType::Sha256).unwrap();
        hasher.update(b"hello world").unwrap();
        println!("{:?}", hasher.finalize().unwrap());
        println!("{:?}", super::super::sha256("hello world").unwrap());

        let mut hash_md5 = Hasher::new(HashType::MD5).unwrap();
        hash_md5.update(b"hello world").unwrap();
        println!("{:?}", hash_md5.finalize().unwrap());

        println!("{:?}", super::super::md5("hello world").unwrap());
    }
}