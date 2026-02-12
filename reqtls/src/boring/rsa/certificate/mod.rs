mod store;

use super::bindings::*;
use crate::boring::bindings::*;
use crate::boring::BoringResExt;
use crate::error::RlsResult;
use crate::RlsError;
use std::ffi::CString;
use std::fs;
use std::path::Path;
use std::ptr::null_mut;
pub use store::{CertStore, ROOT_STORES};
use crate::ffi::{BufPtr, CPointer};

pub struct Certificate {
    x509: CPointer<X509>,
    der: BufPtr,
    pkey: CPointer<EVP_PKEY>,
}

impl Certificate {
    pub fn none() -> Certificate {
        Certificate {
            x509: CPointer::nullptr(),
            der: BufPtr::nullptr(),
            pkey: CPointer::nullptr(),
        }
    }

    pub fn new(x509: CPointer<X509>) -> Certificate {
        Certificate {
            x509,
            der: BufPtr::nullptr(),
            pkey: CPointer::nullptr(),
        }
    }

    pub fn from_der(der: impl AsRef<[u8]>) -> RlsResult<Certificate> {
        let x509 = unsafe { d2i_X509(null_mut(), &mut der.as_ref().as_ptr(), (der.as_ref().len() as u16).into()) };
        Ok(Certificate::new(CPointer::new_checked(x509, RlsError::OpenX509Error)?))
    }

    pub fn from_pem(pem: impl AsRef<[u8]>) -> RlsResult<Vec<Certificate>> {
        let bio = unsafe { BIO_new_mem_buf(pem.as_ref().as_ptr() as *mut _, pem.as_ref().len() as _) };
        let bio = CPointer::new_checked(bio, RlsError::BioNewError)?;
        let mut res = vec![];
        loop {
            let x509 = CPointer::new(unsafe { PEM_read_bio_X509(bio.as_mut_ptr(), null_mut(), None, null_mut()) });
            if x509.is_null() { break; }
            res.push(Certificate::new(x509));
        }
        Ok(res)
    }

    pub fn from_pem_file(pem_file: impl AsRef<Path>) -> RlsResult<Vec<Certificate>> {
        let pem = fs::read(pem_file)?;
        Certificate::from_pem(&pem)
    }

    pub fn as_der(&mut self) -> &BufPtr {
        let len = unsafe { i2d_X509(self.x509.as_mut_ptr(), self.der.ptr_mut()) };
        self.der.set_len(len as usize);
        &self.der
    }

    pub(crate) fn pub_key(&mut self) -> RlsResult<&CPointer<EVP_PKEY>> {
        if self.pkey.is_null() {
            self.pkey = CPointer::new_checked(unsafe { X509_get_pubkey(self.x509.as_mut_ptr()) }, RlsError::PkeyNewError)?;
        }
        Ok(&self.pkey)
    }

    pub fn verify_sni(&self, sni: impl Into<Vec<u8>>) -> RlsResult<()> {
        let sni = sni.into();
        let sni_len = sni.len();
        let c_sni = CString::new(sni)?;
        unsafe { X509_check_host(self.x509.as_mut_ptr(), c_sni.as_ptr(), sni_len, 0, null_mut()) }.ok(RlsError::CertSniInvalid)
    }

    pub fn x509(&self) -> &CPointer<X509> { &self.x509 }
}


