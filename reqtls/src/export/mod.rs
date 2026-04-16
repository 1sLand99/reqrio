use std::ffi::CStr;
use std::os::raw::c_char;
use crate::{Url, UrlError};

mod cipher;
mod hasher;
mod coder;

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn u8_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() { return; }
    let data = unsafe { Vec::from_raw_parts(ptr, len, len) };
    drop(data);
}
