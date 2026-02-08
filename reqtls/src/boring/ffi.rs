use std::ptr::null_mut;
use crate::boring::bindings::*;

pub(crate) struct CPointerMut<T: CFree<T>>(*mut T);
unsafe impl<T: CFree<T>> Send for CPointerMut<T> {}
unsafe impl<T: CFree<T>> Sync for CPointerMut<T> {}
impl<T: CFree<T>> CPointerMut<T> {
    pub fn nullptr() -> Self { CPointerMut(null_mut()) }

    pub fn new(ptr: *mut T) -> Self {
        CPointerMut(ptr)
    }
    pub fn as_mut(&mut self) -> &mut *mut T { &mut self.0 }
    pub fn as_mut_ptr(&self) -> *mut T { self.0 }
    pub fn as_ptr(&self) -> *const T { self.0 }
    pub fn is_null(&self) -> bool { self.0.is_null() }
}

impl<T: CFree<T>> Drop for CPointerMut<T> {
    fn drop(&mut self) {
        T::free_ptr(self.0);
        self.0 = null_mut();
    }
}

pub(crate) trait CFree<T> {
    fn free_ptr(ptr: *mut T);
}

macro_rules! c_pointer_free {
        ($ty:ty, $free_fn:path) => {
            impl crate::boring::ffi::CFree<$ty> for $ty {
                fn free_ptr(ptr: *mut $ty){
                    if !ptr.is_null() { unsafe { $free_fn(ptr as _) } };
                }
            }
        };
    }

c_pointer_free!(EC_KEY, EC_KEY_free);
c_pointer_free!(u8, OPENSSL_free);
c_pointer_free!(EC_POINT, EC_POINT_free);
c_pointer_free!(EVP_PKEY, EVP_PKEY_free);
c_pointer_free!(EVP_PKEY_CTX, EVP_PKEY_CTX_free);