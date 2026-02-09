use std::fmt::{Debug, Formatter};
use std::ptr::null_mut;
use std::slice;
use crate::boring::bindings::*;
use super::rsa::bindings::*;

pub struct CPointer<T: CFree<T>> {
    ptr: *mut T,
    auto_free: bool,
}
unsafe impl<T: CFree<T>> Send for CPointer<T> {}

unsafe impl<T: CFree<T>> Sync for CPointer<T> {}

impl<T: CFree<T>> CPointer<T> {
    pub fn nullptr() -> Self {
        CPointer {
            ptr: null_mut(),
            auto_free: true,
        }
    }

    pub fn new(ptr: *mut T) -> Self {
        CPointer {
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

impl<T: CFree<T>> Drop for CPointer<T> {
    fn drop(&mut self) {
        T::free_ptr(self.ptr, self.auto_free);
        self.ptr = null_mut();
    }
}

pub enum Buf<'a> {
    Ptr(BufPtr),
    Ref(&'a [u8]),
    Vec(Vec<u8>),
}

impl<'a> Buf<'a> {
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Buf::Ptr(v) => v.as_slice(),
            Buf::Ref(v) => v,
            Buf::Vec(v) => v.as_slice(),
        }
    }
}

pub struct BufPtr {
    ptr: CPointer<u8>,
    len: usize,
}

impl BufPtr {
    pub fn nullptr() -> Self {
        BufPtr {
            ptr: CPointer::nullptr(),
            len: 0,
        }
    }

    pub fn is_null(&self) -> bool { self.ptr.is_null() }

    pub fn ptr_mut(&mut self) -> &mut *mut u8 { self.ptr.as_mut() }

    pub fn set_len(&mut self, len: usize) { self.len = len; }

    pub fn len(&self) -> usize { self.len }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

impl Debug for BufPtr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.ptr.is_null() { return write!(f, "nullptr"); }
        let slice = unsafe { slice::from_raw_parts(self.ptr.as_ptr(), self.len) };
        write!(f, "{:?}", slice)
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