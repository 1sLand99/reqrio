use std::ffi::CStr;
use std::os::raw::c_char;
use std::ptr::null_mut;
use reqtls::Url;
use crate::export::{check_run, handle_err1, handle_err2};
use crate::HlsError;

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn Url_new(base_url: *const c_char, err: *mut *mut c_char) -> *mut Url {
    check_run(move || {
        let base_url = unsafe { CStr::from_ptr(base_url) }.to_str()?;
        Ok(Box::into_raw(Box::new(Url::try_from(base_url)?)))
    }, |e| handle_err1(e, err, null_mut()))
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn Url_add_param(url: *mut Url, name: *const c_char, value: *const c_char) -> *mut c_char {
    check_run(move || {
        let url = unsafe { url.as_mut() }.ok_or(HlsError::NullPointer)?;
        let name = unsafe { CStr::from_ptr(name) }.to_str()?;
        let value = unsafe { CStr::from_ptr(value) }.to_str()?;
        url.uri_mut().insert_param(name, value);
        Ok(null_mut())
    }, handle_err2)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn Url_remove_param(url: *mut Url, name: *const c_char) -> *mut c_char {
    check_run(move || {
        let url = unsafe { url.as_mut() }.ok_or(HlsError::NullPointer)?;
        let name = unsafe { CStr::from_ptr(name) }.to_str()?;
        url.uri_mut().remove_param(name);
        Ok(null_mut())
    }, handle_err2)
}