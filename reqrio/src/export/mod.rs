use crate::error::HlsResult;
use crate::{json, UrlExt};
use reqtls::Url;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::ptr::null_mut;

mod req;
mod wss;


#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn Url_new(url: *const c_char, params: *const c_char) -> *mut Url {
    || -> HlsResult<*mut Url> {
        let base_url = unsafe { CStr::from_ptr(url) }.to_str()?;
        let params = unsafe { CStr::from_ptr(params) }.to_str()?;
        let params = json::parse(params)?;
        let url = base_url.params(params)?;
        Ok(Box::into_raw(Box::new(url)))
    }().unwrap_or(null_mut())
}