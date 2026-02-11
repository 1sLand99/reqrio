use crate::boring::ffi::CPointer;
use crate::boring::rsa::bindings::*;
use crate::boring::BoringResExt;
use crate::error::RlsResult;
use crate::{Certificate, RlsError};
use std::ffi::CStr;
use std::sync::LazyLock;

pub static ROOT_STORES: LazyLock<CertStore> = LazyLock::new(|| {
    let certs = Certificate::from_pem(include_bytes!("../../../../roots")).unwrap();
    let mut store = CertStore::empty().unwrap();
    store.extend_certs(certs).unwrap();
    store
});


pub struct CertStore {
    store_ptr: CPointer<X509_STORE>,
    stores: Vec<Certificate>,
}

impl CertStore {
    
    pub fn empty() -> RlsResult<CertStore> {
        let store_ptr = CPointer::new_checked(unsafe { X509_STORE_new() }, RlsError::X509StoreNewError)?;
        Ok(CertStore {
            store_ptr,
            stores: vec![],
        })
    }

    pub fn add_cert(&mut self, cert: Certificate) -> RlsResult<()> {
        unsafe { X509_STORE_add_cert(self.store_ptr.as_mut_ptr(), cert.x509().as_mut_ptr()) }.ok(RlsError::X509StoreAddError)?;
        self.stores.push(cert);
        Ok(())
    }

    pub fn extend_certs(&mut self, certs: Vec<Certificate>) -> RlsResult<()> {
        for cert in certs {
            self.add_cert(cert)?;
        }
        Ok(())
    }

    pub fn pointer(&self) -> &CPointer<X509_STORE> { &self.store_ptr }

    pub fn verify_cert(&self, certs: &[Certificate], sni: &str) -> RlsResult<()> {
        let stack = CPointer::new_checked(unsafe { sk_new_null() }, RlsError::SkNewError)?;
        for cert in &certs[1..] {
            let len = unsafe { sk_push(stack.as_mut_ptr(), cert.x509().as_mut_ptr() as _) };
            if len == 0 { return Err(RlsError::SkPushError); }
        }
        let ctx = CPointer::new_checked(unsafe { X509_STORE_CTX_new() }, RlsError::X509StoreCtxNewError)?;
        unsafe {
            X509_STORE_CTX_init(
                ctx.as_mut_ptr(),
                self.store_ptr.as_mut_ptr(),
                certs[0].x509().as_mut_ptr(),
                stack.as_mut_ptr() as _,
            )
        }.ok(RlsError::X509StoreCtxInitError)?;
        let ret = unsafe { X509_verify_cert(ctx.as_mut_ptr()) };
        if ret != 1 {
            let err = unsafe { X509_STORE_CTX_get_error(ctx.as_mut_ptr()) };
            let msg_prt = unsafe { X509_verify_cert_error_string(err as _) };
            let msg = unsafe { CStr::from_ptr(msg_prt) }.to_string_lossy().to_string();
            return Err(RlsError::Currently(msg));
        };
        certs[0].verify_sni(sni)
    }
}