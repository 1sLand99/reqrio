use std::ffi::CString;
use std::os::raw::c_char;
use std::sync::LazyLock;
use crate::error::RlsResult;
use crate::RlsError;

mod cipher;
mod hasher;
mod coder;
mod url;

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn u8_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() { return; }
    let data = unsafe { Vec::from_raw_parts(ptr, len, len) };
    drop(data);
}

static CONVERT_ERROR: LazyLock<CString> = LazyLock::new(|| unsafe { CString::from_vec_unchecked(b"convert error fail".to_vec()) });

fn handle_err1<T, E: ToString>(e: E, err: *mut *mut c_char, t: T) -> T {
    let ce = CString::new(e.to_string().replace("\0", "")).unwrap_or_else(|_| CONVERT_ERROR.clone());
    unsafe { *err = ce.into_raw(); }
    t
}

fn handle_err2<E: ToString>(e: E) -> *mut c_char {
    let ce = CString::new(e.to_string().replace("\0", "")).unwrap_or_else(|_| CONVERT_ERROR.clone());
    ce.into_raw()
}

fn check_run<T>(mut func: impl FnMut() -> RlsResult<T>, handle: impl Fn(RlsError) -> T) -> T {
    func().unwrap_or_else(handle)
}

