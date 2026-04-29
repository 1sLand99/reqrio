mod url;
mod finger;
mod response;
mod body;

use crate::export::{check_run, handle_err1, handle_err2};
use crate::time::Timeout;
use crate::{json, Body, Cookie, HlsError, Method, Proxy, ReqExt, ReqGenExt, Response, ScReq, ALPN};
use crate::Fingerprint;
use reqtls::Url;
use std::ffi::{c_char, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr::null_mut;

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_new() -> *mut ScReq {
    let sc = ScReq::new();
    Box::into_raw(Box::new(sc))
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_set_header_json(req: *mut ScReq, header: *const c_char) -> *mut c_char {
    check_run(move || {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        let header = unsafe { CStr::from_ptr(header) }.to_bytes();
        let header = json::from_bytes(header)?;
        req.set_headers_json(header)?;
        Ok(null_mut())
    }, handle_err2)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_add_header(req: *mut ScReq, key: *const c_char, value: *const c_char) -> *mut c_char {
    check_run(move || {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        let key = unsafe { CStr::from_ptr(key) }.to_str()?;
        let value = unsafe { CStr::from_ptr(value) }.to_str()?;
        req.header_mut().insert(key, value)?;
        Ok(null_mut())
    }, handle_err2)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_set_alpn(req: *mut ScReq, alpn: *const c_char) -> *mut c_char {
    check_run(move || {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        let alpn = unsafe { CStr::from_ptr(alpn) }.to_bytes();
        let alpn = ALPN::from_slice(alpn);
        req.set_alpn(alpn);
        Ok(null_mut())
    }, handle_err2)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_set_verify(req: *mut ScReq, verify: bool) -> *mut c_char {
    check_run(move || {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        req.set_verify(verify);
        Ok(null_mut())
    }, handle_err2)
}


#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_set_redirect(req: *mut ScReq, redirect: bool) -> *mut c_char {
    check_run(move || {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        req.set_auto_redirect(redirect);
        Ok(null_mut())
    }, handle_err2)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_set_key_log(req: *mut ScReq, key_log: *const c_char) -> *mut c_char {
    check_run(move || {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        let key_log = unsafe { CStr::from_ptr(key_log) }.to_str()?;
        req.set_key_log(key_log);
        Ok(null_mut())
    }, handle_err2)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_set_fingerprint(req: *mut ScReq, fingerprint: *mut Fingerprint) -> *mut c_char {
    check_run(move || {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        req.set_fingerprint(unsafe { *Box::from_raw(fingerprint) });
        Ok(null_mut())
    }, handle_err2)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_set_proxy(req: *mut ScReq, addr: *const c_char) -> *mut c_char {
    check_run(move || {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        let addr = unsafe { CStr::from_ptr(addr) }.to_str()?.to_string();
        let proxy = Proxy::try_from(addr)?;
        req.set_proxy(proxy);
        Ok(null_mut())
    }, handle_err2)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_set_timeout(req: *mut ScReq, timeout: *const c_char) -> *mut c_char {
    check_run(move || {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        let timeout = unsafe { CStr::from_ptr(timeout) }.to_bytes();
        let data = json::from_bytes(timeout)?;
        let timeout = Timeout::try_from(data)?;
        req.set_timeout(timeout);
        Ok(null_mut())
    }, handle_err2)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_set_cookie(req: *mut ScReq, cookie: *const c_char) -> *mut c_char {
    check_run(move || {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        let cookie = unsafe { CStr::from_ptr(cookie) }.to_str()?;
        req.header_mut().set_cookie(cookie)?;
        Ok(null_mut())
    }, handle_err2)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_add_cookie(req: *mut ScReq, name: *const c_char, value: *const c_char) -> *mut c_char {
    check_run(move || {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        let name = unsafe { CStr::from_ptr(name) }.to_str()?;
        let value = unsafe { CStr::from_ptr(value) }.to_str()?;
        let cookie = Cookie::new_cookie(name, value);
        req.header_mut().add_cookie(cookie);
        Ok(null_mut())
    }, handle_err2)
}



#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ScReq_stream_io(
    req: *mut ScReq,
    method: Method,
    url: *mut Url,
    body: *mut Body<'static>,
    err: *mut *mut c_char,
) -> *mut Response {
    catch_unwind(AssertUnwindSafe(|| {
        check_run(move || {
            let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
            req.header_mut().set_method(method);
            let url = unsafe { Box::from_raw(url) };
            let body = unsafe { Box::from_raw(body) };
            let resp = req.stream_io(*url, *body)?;
            Ok(Box::into_raw(Box::new(resp)))
        }, |e| handle_err1(e, err, null_mut()))
    })).unwrap_or_else(|_| handle_err1("程序panic", err, null_mut()))
}
#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_reconnect(req: *mut ScReq, url: *const Url) -> *mut c_char {
    check_run(move || {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        let url = unsafe { url.as_ref() }.ok_or(HlsError::NullPointer)?;
        req.re_conn(url)?;
        Ok(null_mut())
    }, handle_err2)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn ScReq_close_stream(req: *mut ScReq) -> *mut c_char {
    check_run(move || {
        let req = unsafe { req.as_mut() }.ok_or(HlsError::NullPointer)?;
        let _ = req.stream_mut().sync_shutdown();
        Ok(null_mut())
    }, handle_err2)
}


#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn ScReq_drop(req: *mut ScReq) {
    if req.is_null() { return; }
    let mut req = unsafe { Box::from_raw(req) };
    let _ = req.stream_mut().sync_shutdown();
    drop(req);
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn char_free(ptr: *mut c_char) {
    if ptr.is_null() { return; }
    unsafe { let _ = CString::from_raw(ptr); }
}

pub type Callback = extern "C" fn(*const c_char, u32);


#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn ScReq_set_callback(req: *mut ScReq, callback: Callback) -> *mut c_char {
    check_run(move || {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        req.set_callback(move |bs| {
            callback(bs.as_ptr() as *const c_char, bs.len() as u32);
            Ok(())
        });
        Ok(null_mut())
    }, handle_err2)
}












