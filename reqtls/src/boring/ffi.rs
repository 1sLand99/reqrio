use std::ptr::null_mut;
use crate::boring::bindings::*;
use super::rsa::bindings::*;

pub struct CPointerMut<T: CFree<T>> {
    ptr: *mut T,
    auto_free: bool,
}
unsafe impl<T: CFree<T>> Send for CPointerMut<T> {}
unsafe impl<T: CFree<T>> Sync for CPointerMut<T> {}
impl<T: CFree<T>> CPointerMut<T> {
    pub fn nullptr() -> Self {
        CPointerMut {
            ptr: null_mut(),
            auto_free: true,
        }
    }

    pub fn new(ptr: *mut T) -> Self {
        CPointerMut {
            ptr,
            auto_free: true,
        }
    }
    pub fn as_mut(&mut self) -> &mut *mut T { &mut self.ptr }
    pub fn as_mut_ptr(&self) -> *mut T { self.ptr }
    pub fn as_ptr(&self) -> *const T { self.ptr }
    pub fn is_null(&self) -> bool { self.ptr.is_null() }

    pub fn disable_auto_free(&mut self) { self.auto_free = false }
}

impl<T: CFree<T>> Drop for CPointerMut<T> {
    fn drop(&mut self) {
        T::free_ptr(self.ptr,self.auto_free);
        self.ptr = null_mut();
    }
}

pub trait CFree<T> {
    fn free_ptr(ptr: *mut T, free: bool);
}

macro_rules! c_pointer_free {
        ($ty:ty, $free_fn:path) => {
            impl crate::boring::ffi::CFree<$ty> for $ty {
                fn free_ptr(ptr: *mut $ty,free: bool){
                    if !free { return; }
                    if !ptr.is_null() { unsafe { $free_fn(ptr as _); } };
                }
            }
        };
    }

c_pointer_free!(EC_KEY, EC_KEY_free);
c_pointer_free!(u8, OPENSSL_free);
c_pointer_free!(EC_POINT, EC_POINT_free);
c_pointer_free!(EVP_PKEY, EVP_PKEY_free);
c_pointer_free!(EVP_PKEY_CTX, EVP_PKEY_CTX_free);
c_pointer_free!(EVP_CIPHER_CTX, EVP_CIPHER_CTX_free);
c_pointer_free!(EVP_ENCODE_CTX,EVP_ENCODE_CTX_free);
c_pointer_free!(EVP_MD_CTX, EVP_MD_CTX_free);
c_pointer_free!(HMAC_CTX, HMAC_CTX_free);
c_pointer_free!(RSA, RSA_free);
c_pointer_free!(BIGNUM, BN_free);
c_pointer_free!(BIO, BIO_free);
c_pointer_free!(X509, X509_free);