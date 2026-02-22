mod key_usage;

use crate::boring::bindings::EVP_sha256;
use crate::boring::rsa::bindings::*;
use crate::boring::BoringResExt;
use crate::error::RlsResult;
use crate::ffi::CPointer;
use crate::{Certificate, RlsError, RsaKey};
use std::ffi::{c_int, CString};
use std::os::raw::c_long;
use std::ptr::null_mut;

pub struct CertSigner {
    pkey: RsaKey,
    cert: Certificate,
    name: CPointer<X509_NAME>,
    ctx: X509V3_CTX,
}

impl CertSigner {
    pub fn new(key_size: i32) -> RlsResult<CertSigner> {
        let pkey = RsaKey::gen_new_key(key_size)?;
        let x509 = CPointer::new_checked(unsafe { X509_new() }, RlsError::X509NewError)?;
        unsafe { X509_set_version(x509.as_mut_ptr(), 2) }.ok(RlsError::X509SetVersionFail)?;
        //serial
        let serial = CPointer::new_checked(unsafe { ASN1_INTEGER_new() }, RlsError::NewAsn1IntegerError)?;
        unsafe { ASN1_INTEGER_set(serial.as_mut_ptr(), 1); }
        unsafe { X509_set_serialNumber(x509.as_mut_ptr(), serial.as_ptr()); }
        //pubkey
        unsafe { X509_set_pubkey(x509.as_mut_ptr(), pkey.pkey().as_mut_ptr()); }
        let name = CPointer::new_checked(unsafe { X509_NAME_new() }, RlsError::NewX509NameError)?;
        Ok(CertSigner {
            pkey,
            name,
            ctx: X509V3_CTX {
                flags: 0,
                issuer_cert: x509.as_ptr(),
                subject_cert: x509.as_ptr(),
                subject_req: null_mut(),
                crl: null_mut(),
                db: null_mut(),
            },
            cert: Certificate::new(x509),
        })
    }

    pub fn set_expire(&mut self, years: c_long) -> RlsResult<()> {
        unsafe { X509_gmtime_adj(X509_get_notBefore(self.cert.x509().as_ptr()), 0); }
        unsafe { X509_gmtime_adj(X509_get_notAfter(self.cert.x509().as_ptr()), 60 * 60 * 24 * 365 * years); }
        Ok(())
    }

    pub fn add_subject(&self, field: impl AsRef<str>, value: impl AsRef<str>) -> RlsResult<()> {
        let field = CString::new(field.as_ref())?;
        let value = CString::new(value.as_ref())?;
        unsafe {
            X509_NAME_add_entry_by_txt(
                self.name.as_mut_ptr(),
                field.as_ptr(),
                MBSTRING_ASC,
                value.as_ptr() as *const u8,
                -1,
                -1,
                0,
            ).ok(RlsError::X509AddNameError)
        }
    }

    pub fn add_extension(&mut self, nid: c_int, value: impl AsRef<str>) -> RlsResult<()> {
        let value = CString::new(value.as_ref())?;
        let ext = unsafe {
            X509V3_EXT_nconf_nid(
                null_mut(),
                &mut self.ctx,
                nid,
                value.as_ptr(),
            )
        };
        let ext = CPointer::new_checked(ext, RlsError::NewX509ExtError)?;
        unsafe { X509_add_ext(self.cert.x509().as_mut_ptr(), ext.as_ptr(), -1) }.ok(RlsError::X509AddExtFail)
    }

    pub fn sign_self(&mut self) -> RlsResult<()> {
        unsafe { X509_set_subject_name(self.cert.x509().as_mut_ptr(), self.name.as_ptr()) }.ok(RlsError::X509SetSubjectError)?;
        unsafe { X509_set_issuer_name(self.cert.x509().as_mut_ptr(), self.name.as_ptr()) }.ok(RlsError::X509SetIssuerError)?;
        //sign
        let ret = unsafe { X509_sign(self.cert.x509().as_mut_ptr(), self.pkey.pkey().as_mut_ptr(), EVP_sha256()) };
        if ret <= 0 { return Err(RlsError::X509SignError); }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::boring::certificate::siger::CertSigner;
    use crate::boring::rsa::bindings::{NID_basic_constraints, NID_key_usage, NID_subject_key_identifier};
    use std::fs;

    #[test]
    fn test_generate_root_ca() {
        let mut signer = CertSigner::new(2048).unwrap();
        signer.set_expire(10).unwrap();
        signer.add_subject("C", "CC").unwrap();
        signer.add_subject("O", "OO").unwrap();
        signer.add_subject("CN", "CNN").unwrap();
        signer.add_extension(NID_basic_constraints, "critical,CA:TRUE").unwrap();
        signer.add_extension(NID_key_usage, "critical,keyCertSign,cRLSign").unwrap();
        signer.add_extension(NID_subject_key_identifier, "hash").unwrap();
        signer.sign_self().unwrap();
        fs::write("2.der", signer.cert.as_der().as_slice()).unwrap()
    }
}