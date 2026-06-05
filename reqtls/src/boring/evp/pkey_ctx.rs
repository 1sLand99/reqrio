use std::error::Error;
use std::fmt::{Display, Formatter};
use std::ops::{Deref, DerefMut};
use std::os::raw::c_int;
use crate::boring::BoringResExt;
use crate::ffi;
use crate::ffi::CPointer;
use super::{PKEY, PKey};

#[derive(Debug)]
pub enum PKeyError {
    NewCtxFail,
    KeygenInitFail,
    KeygenFail,
    GetRawPubKeyError,
    GetRawPriKeyError,
    InvalidPubKey,
    InvalidPriKey,
    DiffieHellmanError
}

impl Display for PKeyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for PKeyError {}

#[repr(C)]
#[allow(clippy::upper_case_acronyms)]
#[allow(non_camel_case_types)]
pub struct PKEY_CTX {
    _unused: [u8; 0],
}

ffi::c_pointer_free!(PKEY_CTX, PKEY_CTX_free);

unsafe extern "C" {
    fn PKEY_CTX_new_id(nid: c_int) -> *mut PKEY_CTX;
    fn PKEY_CTX_new(key: *const PKEY) -> *mut PKEY_CTX;
    fn PKEY_CTX_free(ctx: *mut PKEY_CTX);
    fn PKEY_keygen_init(ctx: *const PKEY_CTX) -> c_int;
    fn PKEY_keygen(ctx: *const PKEY_CTX) -> *mut PKEY;
}

pub struct PKeyCtx(CPointer<PKEY_CTX>);

impl PKeyCtx {
    pub fn new_nid(nid: i32) -> Result<PKeyCtx, PKeyError> {
        let ptr = unsafe { PKEY_CTX_new_id(nid) };
        let ptr = CPointer::new_checked(ptr, PKeyError::NewCtxFail)?;
        Ok(PKeyCtx(ptr))
    }

    pub fn new(pkey: PKey) -> Result<PKeyCtx, PKeyError> {
        let ptr = unsafe { PKEY_CTX_new(pkey.as_mut_ptr()) };
        let ptr = CPointer::new_checked(ptr, PKeyError::NewCtxFail)?;
        Ok(PKeyCtx(ptr))
    }

    pub fn keygen_init(&self) -> Result<(), PKeyError> {
        unsafe { PKEY_keygen_init(self.as_ptr()) }.ok(PKeyError::KeygenInitFail)
    }

    pub fn keygen(&self) -> Result<PKey, PKeyError> {
        let key = unsafe { PKEY_keygen(self.as_ptr()) };
        let key = CPointer::new_checked(key, PKeyError::KeygenFail)?;
        Ok(PKey::new(key))
    }

    pub fn generate_key(&self) -> Result<PKey, PKeyError> {
        unsafe { PKEY_keygen_init(self.as_ptr()) }.ok(PKeyError::KeygenInitFail)?;
        let key = unsafe { PKEY_keygen(self.as_ptr()) };
        let key = CPointer::new_checked(key, PKeyError::KeygenFail)?;
        Ok(PKey::new(key))
    }
}

impl Deref for PKeyCtx {
    type Target = CPointer<PKEY_CTX>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for PKeyCtx {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}