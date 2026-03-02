use crate::error::RlsResult;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr::null_mut;
use std::slice;
use crate::base64::Base64;
use crate::RlsError;

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn url_encode(url: *const c_char) -> *mut c_char {
    || -> RlsResult<*mut c_char> {
        let uri = unsafe { CStr::from_ptr(url) }.to_str()?;
        let res = crate::coder::url_encode(uri);
        Ok(CString::new(res)?.into_raw())
    }().unwrap_or(null_mut())
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn url_decode(url: *const c_char) -> *mut c_char {
    || -> RlsResult<*mut c_char> {
        let uri = unsafe { CStr::from_ptr(url) }.to_str()?;
        let res = crate::coder::url_decode(uri)?;
        Ok(CString::new(res)?.into_raw())
    }().unwrap_or(null_mut())
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn hex_decode(url: *const c_char) -> *mut c_char {
    || -> RlsResult<*mut c_char> {
        let uri = unsafe { CStr::from_ptr(url) }.to_str()?;
        let res = hex::decode(uri)?;
        Ok(CString::new(res)?.into_raw())
    }().unwrap_or(null_mut())
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn hex_encode(url: *const c_char) -> *mut c_char {
    || -> RlsResult<*mut c_char> {
        let uri = unsafe { CStr::from_ptr(url) }.to_str()?;
        let res = hex::encode(uri);
        Ok(CString::new(res)?.into_raw())
    }().unwrap_or(null_mut())
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub fn Base64_new() -> *mut Base64 {
    Box::into_raw(Box::new(Base64::new()))
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub fn Base64_decode(base64: *mut Base64, data: *const u8, len: u32) -> *mut c_char {
    || -> RlsResult<*mut c_char> {
        let base64 = unsafe { base64.as_mut() }.ok_or(RlsError::NullPtr)?;
        let data = unsafe { slice::from_raw_parts(data, len as usize) };
        let res = base64.decode(data)?;
        Ok(CString::new(res)?.into_raw())
    }().unwrap_or(null_mut())
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub fn Base64_encode(base64: *mut Base64, data: *const u8, len: u32) -> *mut c_char {
    || -> RlsResult<*mut c_char> {
        let base64 = unsafe { base64.as_mut() }.ok_or(RlsError::NullPtr)?;
        let data = unsafe { slice::from_raw_parts(data, len as usize) };
        let res = base64.encode(data);
        Ok(CString::new(res)?.into_raw())
    }().unwrap_or(null_mut())
}


#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub fn Base64_free(base64: *mut Base64) {
    if base64.is_null() { return; }
    let base64 = unsafe { Box::from_raw(base64) };
    drop(base64);
}

