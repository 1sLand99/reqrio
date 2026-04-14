use crate::boring::bindings::{EVP_PKEY_new, EVP_PKEY};
use crate::boring::rsa::bindings::*;
use crate::boring::BoringResExt;
use crate::error::RlsResult;
use crate::ffi::CPointer;
use crate::{BufferError, RlsError};
use crate::RlsError::WritePubKeyError;
use std::os::raw::c_long;
use std::path::Path;
use std::ptr::null_mut;
use std::{fs, slice};
use crate::buffer::BufPtr;

pub struct RsaKey(CPointer<EVP_PKEY>);

impl RsaKey {
    pub fn none() -> RsaKey {
        RsaKey(CPointer::nullptr())
    }

    fn new(mut rsa: CPointer<RSA>) -> RlsResult<RsaKey> {
        let pkey = CPointer::new_checked(unsafe { EVP_PKEY_new() }, RlsError::PkeyNewError)?;
        unsafe { EVP_PKEY_assign_RSA(pkey.as_mut_ptr(), rsa.as_mut_ptr()) }.ok(RlsError::PkeyAssignError)?;
        rsa.disable_auto_free();
        Ok(RsaKey(pkey))
    }
    pub fn gen_new_key(bits: i32) -> RlsResult<RsaKey> {
        let rsa = CPointer::new_checked(unsafe { RSA_new() }, RlsError::RsaNewError)?;
        let e = CPointer::new_checked(unsafe { BN_new() }, RlsError::BnNewError)?;
        unsafe { BN_set_word(e.as_mut_ptr(), RSA_F4 as u64) }.ok(RlsError::BnSetWordError)?;
        unsafe { RSA_generate_key_ex(rsa.as_mut_ptr(), bits, e.as_mut_ptr(), null_mut()) }.ok(RlsError::RsaGenKeyError)?;
        RsaKey::new(rsa)
    }

    pub fn to_pri_pem(&self) -> RlsResult<String> {
        let bio = CPointer::new_checked(unsafe { BIO_new(BIO_s_mem()) }, RlsError::BioNewError)?;
        unsafe {
            PEM_write_bio_PrivateKey(
                bio.as_mut_ptr(),
                self.0.as_mut_ptr(),
                null_mut(),
                null_mut(),
                0,
                None,
                null_mut(),
            )
        }.ok(RlsError::WritePriKeyError)?;
        let mut data = null_mut();
        let len = unsafe { BIO_get_mem_data(bio.as_mut_ptr(), &mut data) };
        if len == c_long::MAX || data.is_null() { return Err(RlsError::WritePriKeyError); }
        let out = unsafe { slice::from_raw_parts(data as *const u8, len as usize) }.to_vec();
        Ok(String::from_utf8(out)?)
    }

    pub fn to_pub_pem(&self) -> RlsResult<String> {
        let bio = CPointer::new_checked(unsafe { BIO_new(BIO_s_mem()) }, RlsError::BioNewError)?;
        unsafe { PEM_write_bio_PUBKEY(bio.as_mut_ptr(), self.0.as_mut_ptr()) }.ok(WritePubKeyError)?;
        let mut data = null_mut();
        let len = unsafe { BIO_get_mem_data(bio.as_mut_ptr(), &mut data) };
        if len <= 0 || len == c_long::MAX || data.is_null() { return Err(WritePubKeyError); }
        let out = unsafe { slice::from_raw_parts(data as *const u8, len as usize) }.to_vec();
        Ok(String::from_utf8(out)?)
    }

    pub fn to_pri_der(&self) -> Result<BufPtr, BufferError> {
        let mut buf = BufPtr::nullptr();
        let len = unsafe { i2d_PrivateKey(self.0.as_ptr(), buf.ptr_mut()) };
        buf.check_ptr(len as usize)?;
        Ok(buf)
    }

    pub fn to_pub_der(&self) -> Result<BufPtr, BufferError> {
        let mut buf = BufPtr::nullptr();
        let len = unsafe { i2d_PUBKEY(self.0.as_ptr(), buf.ptr_mut()) };
        buf.check_ptr(len as usize)?;
        Ok(buf)
    }

    pub fn from_pri_pem(pem: impl AsRef<[u8]>) -> RlsResult<RsaKey> {
        let bio = CPointer::new(unsafe { BIO_new_mem_buf(pem.as_ref().as_ptr() as *const _, pem.as_ref().len() as isize) });
        if bio.is_null() { return Err(RlsError::BioNewError); }
        let pkey = CPointer::new(unsafe { PEM_read_bio_PrivateKey(bio.as_mut_ptr(), null_mut(), None, null_mut()) });
        if pkey.is_null() { return Err(RlsError::BioNewError); }
        Ok(RsaKey(pkey))
    }

    pub fn from_pri_pem_file(pem_file: impl AsRef<Path>) -> RlsResult<RsaKey> {
        let pem = fs::read(pem_file)?;
        RsaKey::from_pri_pem(pem)
    }

    pub fn from_pub_pem(pem: impl AsRef<[u8]>) -> RlsResult<RsaKey> {
        let bio = CPointer::new(unsafe { BIO_new_mem_buf(pem.as_ref().as_ptr() as *const _, pem.as_ref().len() as isize) });
        if bio.is_null() { return Err(RlsError::BioNewError); }
        let pkey = CPointer::new(unsafe { PEM_read_bio_PUBKEY(bio.as_mut_ptr(), null_mut(), None, null_mut()) });
        if pkey.is_null() { return Err(RlsError::PkeyNewError); };
        Ok(RsaKey(pkey))
    }

    pub fn from_pri_der(der: impl AsRef<[u8]>) -> RlsResult<RsaKey> {
        let pkey = CPointer::new(unsafe { d2i_AutoPrivateKey(null_mut(), &mut der.as_ref().as_ptr(), (der.as_ref().len() as u16).into()) });
        if pkey.is_null() { return Err(RlsError::PkeyNewError); };
        Ok(RsaKey(pkey))
    }

    pub fn from_pub_der(der: impl AsRef<[u8]>) -> RlsResult<RsaKey> {
        let pkey = CPointer::new(unsafe { d2i_PUBKEY(null_mut(), &mut der.as_ref().as_ptr(), (der.as_ref().len() as u16).into()) });
        if pkey.is_null() { return Err(RlsError::PkeyNewError); };
        Ok(RsaKey(pkey))
    }

    pub fn from_e_n(e: impl AsRef<[u8]>, n: impl AsRef<[u8]>) -> RlsResult<RsaKey> {
        let e = hex::decode(e)?;
        let n = hex::decode(n)?;
        let mut e = CPointer::new_checked(unsafe { BN_bin2bn(e.as_ptr(), e.len(), null_mut()) }, RlsError::BnNewError)?;
        let mut n = CPointer::new_checked(unsafe { BN_bin2bn(n.as_ptr(), n.len(), null_mut()) }, RlsError::BnNewError)?;
        let rsa = CPointer::new_checked(unsafe { RSA_new() }, RlsError::RsaNewError)?;
        unsafe { RSA_set0_key(rsa.as_mut_ptr(), n.as_mut_ptr(), e.as_mut_ptr(), null_mut()) }.ok(RlsError::RsaGenKeyError)?;
        e.disable_auto_free();
        n.disable_auto_free();
        RsaKey::new(rsa)
    }

    pub fn pkey(&self) -> &CPointer<EVP_PKEY> {
        &self.0
    }
}
