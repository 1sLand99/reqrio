use std::ffi::CString;
use std::path::Path;
use std::ptr::null_mut;
use std::{fs, slice};
use crate::boring::bindings::*;
use crate::boring::BoringResExt;
use super::bindings::*;
use crate::error::RlsResult;
use crate::RlsError;

#[derive(Clone)]
pub struct Certificate {
    x509: *mut X509,
    pkey: *mut EVP_PKEY,
    der: *mut u8,
    len: usize,
}

impl Certificate {
    pub fn none() -> Certificate {
        Certificate {
            x509: null_mut(),
            pkey: null_mut(),
            der: null_mut(),
            len: 0,
        }
    }

    pub fn new(x509: *mut X509) -> Certificate {
        Certificate {
            x509,
            pkey: null_mut(),
            der: null_mut(),
            len: 0,
        }
    }

    pub fn from_der(der: impl AsRef<[u8]>) -> RlsResult<Certificate> {
        let x509 = unsafe { d2i_X509(null_mut(), &mut der.as_ref().as_ptr(), (der.as_ref().len() as u16).into()) };
        if x509.is_null() { return Err(RlsError::OpenX509Error); }
        Ok(Certificate::new(x509))
    }

    pub fn from_pem(pem: impl AsRef<[u8]>) -> RlsResult<Vec<Certificate>> {
        let bio = unsafe { BIO_new_mem_buf(pem.as_ref().as_ptr() as *mut _, pem.as_ref().len() as _) };
        if bio.is_null() { return Err(RlsError::BioNewError); }
        let mut res = vec![];
        loop {
            let x509 = unsafe { PEM_read_bio_X509(bio, null_mut(), None, null_mut()) };
            if x509.is_null() { break; }
            res.push(Certificate::new(x509));
        }
        unsafe { BIO_free(bio); }
        Ok(res)
    }

    pub fn from_pem_file(pem_file: impl AsRef<Path>) -> RlsResult<Vec<Certificate>> {
        let pem = fs::read(pem_file)?;
        Certificate::from_pem(&pem)
    }

    pub fn as_der(&mut self) -> &[u8] {
        if self.der.is_null() {
            self.len = unsafe { i2d_X509(self.x509, &mut self.der) } as usize;
        }
        unsafe { slice::from_raw_parts(self.der, self.len) }
    }

    pub(crate) fn pub_key(&mut self) -> RlsResult<*mut EVP_PKEY> {
        if self.pkey.is_null() {
            self.pkey = unsafe { X509_get_pubkey(self.x509) };
            if self.pkey.is_null() { return Err(RlsError::PkeyNewError); }
        }
        Ok(self.pkey)
    }

    pub fn verify_sni(&self, sni: impl Into<Vec<u8>>) -> RlsResult<()> {
        let sni = sni.into();
        let sni_len = sni.len();
        let c_sni = CString::new(sni)?;
        unsafe { X509_check_host(self.x509, c_sni.as_ptr(), sni_len, 0, null_mut()) }.ok(RlsError::CertSniInvalid)
    }
}

impl Drop for Certificate {
    fn drop(&mut self) {
        unsafe {
            if !self.pkey.is_null() { EVP_PKEY_free(self.pkey); }
            if !self.x509.is_null() { X509_free(self.x509); }
            if !self.der.is_null() { OPENSSL_free(self.der as *mut _); }
        }
    }
}