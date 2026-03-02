mod store;
mod siger;
mod cert_type;

use super::bindings::*;
use crate::boring::bindings::*;
pub use cert_type::CertType;
use crate::boring::BoringResExt;
use crate::error::RlsResult;
use crate::ffi::{BufPtr, CPointer};
use crate::RlsError;
pub use siger::{BasicConstraint, CertExtend, CertSigner, DnType, KeyIdentifier, KeyUsage, SubjectAltName};
use std::ffi::CString;
use std::path::Path;
use std::ptr::null_mut;
use std::{fs, slice};
pub use store::{CertStore, ROOT_STORES};

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

    pub(crate) fn is_none(&self) -> bool {
        self.x509.is_null()
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
        if self.der.is_null() {
            let len = unsafe { i2d_X509(self.x509.as_mut_ptr(), self.der.ptr_mut()) };
            self.der.set_len(len as usize);
        }
        &self.der
    }

    pub fn as_pem(&mut self) -> RlsResult<String> {
        let bio = unsafe { BIO_new(BIO_s_mem()) };
        let bio = CPointer::new_checked(bio, RlsError::BioNewError)?;
        unsafe { PEM_write_bio_X509(bio.as_mut_ptr(), self.x509.as_mut_ptr()) }.ok(RlsError::BIOWriteError)?;
        let mut buf = null_mut();
        let len = unsafe { BIO_get_mem_data(bio.as_mut_ptr(), &mut buf) };
        if len <= 0 { return Err(RlsError::BIOGetDataError); };
        let out = unsafe { slice::from_raw_parts(buf as *const u8, len as usize) };
        Ok(String::from_utf8_lossy(out).to_string())
    }

    pub fn pub_key(&mut self) -> RlsResult<&CPointer<EVP_PKEY>> {
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

    ///Authority Information Access
    pub fn get_aia(&self) -> RlsResult<Vec<String>> {
        let mut crit = 0;
        let aia = unsafe {
            X509_get_ext_d2i(
                self.x509.as_ptr(),
                NID_info_access,
                &mut crit,
                null_mut(),
            )
        } as *mut AUTHORITY_INFO_ACCESS;
        let aia = CPointer::new_checked(aia, RlsError::GetAiaFail)?;
        let count = unsafe { sk_num(aia.as_ptr() as _) };
        let mut res = vec![];
        for i in 0..count {
            let ad = unsafe { sk_value(aia.as_ptr() as _, i) } as *mut ACCESS_DESCRIPTION;
            let nid = unsafe { OBJ_obj2nid((*ad).method) };
            let location = unsafe { (*ad).location.as_mut() }.ok_or(RlsError::NullPtr)?;
            if nid == NID_ad_ca_issuers && location.type_ == GEN_URI {
                let uri = unsafe { location.d.uniformResourceIdentifier };
                let data = unsafe { ASN1_STRING_get0_data(uri as _) };
                let len = unsafe { ASN1_STRING_length(uri as _) };
                let slice = unsafe { std::slice::from_raw_parts(data, len as _) };
                res.push(String::from_utf8_lossy(slice).to_string())
            }
        }
        Ok(res)
    }

    pub fn cert_type(&mut self) -> RlsResult<CertType> {
        let pkey = self.pub_key()?;
        let key_type = unsafe { EVP_PKEY_id(pkey.as_ptr()) };
        match key_type {
            EVP_PKEY_RSA => Ok(CertType::RSA),
            EVP_PKEY_EC => Ok(CertType::ECDSA),
            EVP_PKEY_ED25519 => Ok(CertType::ED25519),
            _ => Ok(CertType::new(0)),
        }
    }
}


