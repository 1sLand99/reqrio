use std::ffi::CString;
use std::ptr::null_mut;
use crate::boring::bindings::*;
use crate::boring::BoringResExt;
use crate::error::RlsResult;
use crate::RlsError;

pub struct Certificate {
    x509: *mut X509,
    pkey: *mut EVP_PKEY,
}

impl Certificate {
    pub fn none() -> Certificate {
        Certificate {
            x509: null_mut(),
            pkey: null_mut(),
        }
    }
    pub fn from_der(der: impl AsRef<[u8]>) -> RlsResult<Certificate> {
        let x509 = unsafe { d2i_X509(null_mut(), &mut der.as_ref().as_ptr(), (der.as_ref().len() as u16).into()) };
        if x509.is_null() { return Err(RlsError::OpenX509Error); }
        Ok(Certificate {
            x509,
            pkey: null_mut(),
        })
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
            EVP_PKEY_free(self.pkey);
            X509_free(self.x509);
        }
    }
}