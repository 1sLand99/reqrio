use std::ptr::null_mut;
pub use hmac::Hmac;
pub use hasher::Hasher;
use crate::boring::bindings::*;
use crate::error::RlsResult;
use crate::RlsError;

pub mod hmac;
mod hasher;

#[derive(Clone, Copy)]
pub enum Sha {
    MD5,
    Sha1,
    Sha256,
    Sha384,
    Sha512,

}

impl Sha {
    pub fn evp_md(&self) -> *const EVP_MD {
        match self {
            Sha::MD5 => unsafe { EVP_md5() },
            Sha::Sha1 => unsafe { EVP_sha1() },
            Sha::Sha256 => unsafe { EVP_sha256() },
            Sha::Sha384 => unsafe { EVP_sha384() },
            Sha::Sha512 => unsafe { EVP_sha512() },
        }
    }

    pub(crate) fn hash_size(&self) -> usize {
        match self {
            Sha::MD5 => 32,
            Sha::Sha1 => 20,
            Sha::Sha256 => 32,
            Sha::Sha384 => 48,
            Sha::Sha512 => 64
        }
    }
}

fn digest(data: &[u8], out: *mut u8, sha: Sha) -> RlsResult<usize> {
    let mut len = 0;
    let ret = unsafe {
        EVP_Digest(
            data.as_ptr() as *const _,
            data.len(),
            out as *mut _,
            &mut len,
            sha.evp_md(),
            null_mut(),
        )
    };
    if ret != 1 { return Err(RlsError::DigestUpdateError); }
    Ok(len as usize)
}

pub fn md5(context: impl AsRef<[u8]>) -> RlsResult<[u8; 16]> {
    let mut out = [0u8; 16];
    digest(context.as_ref(), out.as_mut_ptr(), Sha::MD5)?;
    Ok(out)
}

pub fn sha1(context: impl AsRef<[u8]>) -> RlsResult<[u8; 20]> {
    let mut out = [0u8; 20];
    digest(context.as_ref(), out.as_mut_ptr(), Sha::Sha1)?;
    Ok(out)
}

pub fn sha256(context: impl AsRef<[u8]>) -> RlsResult<[u8; 32]> {
    let mut out = [0u8; 32];
    digest(context.as_ref(), out.as_mut_ptr(), Sha::Sha256)?;
    Ok(out)
}

pub fn sha384(context: impl AsRef<[u8]>) -> RlsResult<[u8; 48]> {
    let mut out = [0u8; 48];
    digest(context.as_ref(), out.as_mut_ptr(), Sha::Sha384)?;
    Ok(out)
}

pub fn sha512(context: impl AsRef<[u8]>) -> RlsResult<[u8; 64]> {
    let mut out = [0u8; 64];
    digest(context.as_ref(), out.as_mut_ptr(), Sha::Sha512)?;
    Ok(out)
}