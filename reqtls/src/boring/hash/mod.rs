pub mod hmac;
mod hasher;
mod error;

use crate::boring::bindings::*;
use crate::error::RlsResult;
pub use error::HashError;
pub use hasher::Hasher;
pub use hmac::Hmac;
use std::ptr::null_mut;


#[derive(Clone, Copy)]
#[cfg_attr(feature = "export", repr(C))]
pub enum HashType {
    MD5 = 0,
    Sha1 = 1,
    Sha224 = 2,
    Sha256 = 3,
    Sha384 = 4,
    Sha512 = 5,

}

impl HashType {
    pub fn evp_md(&self) -> *const EVP_MD {
        match self {
            HashType::MD5 => unsafe { EVP_md5() },
            HashType::Sha224 => unsafe { EVP_sha224() }
            HashType::Sha1 => unsafe { EVP_sha1() },
            HashType::Sha256 => unsafe { EVP_sha256() },
            HashType::Sha384 => unsafe { EVP_sha384() },
            HashType::Sha512 => unsafe { EVP_sha512() },
        }
    }

    pub(crate) fn hash_size(&self) -> usize {
        match self {
            HashType::MD5 => 32,
            HashType::Sha1 => 20,
            HashType::Sha224 => 28,
            HashType::Sha256 => 32,
            HashType::Sha384 => 48,
            HashType::Sha512 => 64
        }
    }
}

fn digest(data: &[u8], out: *mut u8, sha: HashType) -> Result<usize, HashError> {
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
    if ret != 1 { return Err(HashError::DigestUpdateError); }
    Ok(len as usize)
}

pub fn md5(context: impl AsRef<[u8]>) -> RlsResult<[u8; 16]> {
    let mut out = [0u8; 16];
    digest(context.as_ref(), out.as_mut_ptr(), HashType::MD5)?;
    Ok(out)
}

pub fn md5_hex(context: impl AsRef<[u8]>) -> RlsResult<String> {
    Ok(hex::encode(md5(context)?))
}

pub fn sha1(context: impl AsRef<[u8]>) -> RlsResult<[u8; 20]> {
    let mut out = [0u8; 20];
    digest(context.as_ref(), out.as_mut_ptr(), HashType::Sha1)?;
    Ok(out)
}

pub fn sha1_hex(context: impl AsRef<[u8]>) -> RlsResult<String> {
    Ok(hex::encode(sha1(context)?))
}

pub fn sha224(context: impl AsRef<[u8]>) -> RlsResult<[u8; 28]> {
    let mut out = [0u8; 28];
    digest(context.as_ref(), out.as_mut_ptr(), HashType::Sha224)?;
    Ok(out)
}

pub fn sha224_hex(context: impl AsRef<[u8]>) -> RlsResult<String> {
    Ok(hex::encode(sha224(context)?))
}

pub fn sha256(context: impl AsRef<[u8]>) -> RlsResult<[u8; 32]> {
    let mut out = [0u8; 32];
    digest(context.as_ref(), out.as_mut_ptr(), HashType::Sha256)?;
    Ok(out)
}

pub fn sha256_hex(context: impl AsRef<[u8]>) -> RlsResult<String> {
    Ok(hex::encode(sha256(context)?))
}

pub fn sha384(context: impl AsRef<[u8]>) -> RlsResult<[u8; 48]> {
    let mut out = [0u8; 48];
    digest(context.as_ref(), out.as_mut_ptr(), HashType::Sha384)?;
    Ok(out)
}

pub fn sha384_hex(context: impl AsRef<[u8]>) -> RlsResult<String> {
    Ok(hex::encode(sha384(context)?))
}

pub fn sha512(context: impl AsRef<[u8]>) -> RlsResult<[u8; 64]> {
    let mut out = [0u8; 64];
    digest(context.as_ref(), out.as_mut_ptr(), HashType::Sha512)?;
    Ok(out)
}

pub fn sha512_hex(context: impl AsRef<[u8]>) -> RlsResult<String> {
    Ok(hex::encode(sha512(context)?))
}