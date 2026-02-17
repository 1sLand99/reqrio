use crate::error::HlsResult;
use crate::timeout::Timeout;
use crate::Fingerprint;
use crate::{json, Cookie, HlsError, Method, Proxy, ReqExt, ScReq, ALPN};
use reqtls::hex;
use std::ffi::{c_char, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_new() -> *mut ScReq {
    let sc = ScReq::new();
    Box::into_raw(Box::new(sc))
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_set_header_json(req: *mut ScReq, header: *const c_char) -> i32 {
    || -> HlsResult<i32> {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        let header = unsafe { CStr::from_ptr(header) }.to_bytes();
        let header = json::from_bytes(header)?;
        req.set_headers_json(header)?;
        Ok(0)
    }().unwrap_or(-1)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_add_header(req: *mut ScReq, key: *const c_char, value: *const c_char) -> i32 {
    || -> HlsResult<i32> {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        let key = unsafe { CStr::from_ptr(key) }.to_str()?;
        let value = unsafe { CStr::from_ptr(value) }.to_str()?;
        req.header_mut().insert(key, value)?;
        Ok(0)
    }().unwrap_or(-1)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_set_alpn(req: *mut ScReq, alpn: *const c_char) -> i32 {
    || -> HlsResult<i32> {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        let alpn = unsafe { CStr::from_ptr(alpn) }.to_bytes();
        let alpn = ALPN::from_slice(alpn);
        req.set_alpn(alpn);
        Ok(0)
    }().unwrap_or(-1)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_set_random_fingerprint(req: *mut ScReq, token: *const c_char) -> i32 {
    || -> HlsResult<i32> {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        let token = unsafe { CStr::from_ptr(token) }.to_str()?;
        let fingerprint = Fingerprint::random(token)?;
        let ret = fingerprint.legal_subscript();
        req.set_fingerprint(fingerprint);
        Ok(ret)
    }().unwrap_or(-1)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_set_fingerprint(req: *mut ScReq, fingerprint: *const c_char, token: *const c_char) -> i32 {
    || -> HlsResult<i32> {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        let fingerprint = unsafe { CStr::from_ptr(fingerprint) }.to_str()?.to_string();
        let token = unsafe { CStr::from_ptr(token) }.to_str()?;
        let fingerprint = Fingerprint::from_hex_all(fingerprint, token)?;
        let ret = fingerprint.legal_subscript();
        req.set_fingerprint(fingerprint);
        Ok(ret)
    }().unwrap_or(-1)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_set_ja3(req: *mut ScReq, ja3: *const c_char, token: *const c_char) -> i32 {
    || -> HlsResult<i32> {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        let ja3 = unsafe { CStr::from_ptr(ja3) }.to_str()?.to_string();
        let token = unsafe { CStr::from_ptr(token) }.to_str()?;
        let fingerprint = Fingerprint::new_ja3(ja3, token)?;
        let ret = fingerprint.legal_subscript();
        req.set_fingerprint(fingerprint);
        Ok(ret)
    }().unwrap_or(-1)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_set_ja4(req: *mut ScReq, ja4: *const c_char, token: *const c_char) -> i32 {
    || -> HlsResult<i32> {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        let ja4 = unsafe { CStr::from_ptr(ja4) }.to_str()?.to_string();
        let token = unsafe { CStr::from_ptr(token) }.to_str()?;
        let fingerprint = Fingerprint::new_ja4(ja4, token)?;
        let ret = fingerprint.legal_subscript();
        req.set_fingerprint(fingerprint);
        Ok(ret)
    }().unwrap_or(-1)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_set_proxy(req: *mut ScReq, addr: *const c_char) -> i32 {
    || -> HlsResult<i32> {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        let addr = unsafe { CStr::from_ptr(addr) }.to_str()?.to_string();
        let proxy = Proxy::try_from(addr)?;
        req.set_proxy(proxy);
        Ok(0)
    }().unwrap_or(-1)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_set_url(req: *mut ScReq, url: *const c_char) -> i32 {
    || -> HlsResult<i32> {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        let url = unsafe { CStr::from_ptr(url) }.to_str()?.to_string();
        req.set_url(url)?;
        Ok(0)
    }().unwrap_or(-1)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_add_param(req: *mut ScReq, name: *const c_char, value: *const c_char) -> i32 {
    || -> HlsResult<i32> {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        let name = unsafe { CStr::from_ptr(name) }.to_str()?.to_string();
        let value = unsafe { CStr::from_ptr(value) }.to_str()?.to_string();
        req.add_param(&name, &value);
        Ok(0)
    }().unwrap_or(-1)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_set_data(req: *mut ScReq, data: *const c_char) -> i32 {
    || -> HlsResult<i32> {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        let data = unsafe { CStr::from_ptr(data) }.to_bytes();
        let data = json::from_bytes(data)?;
        req.set_data(data);
        Ok(0)
    }().unwrap_or(-1)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_set_json(req: *mut ScReq, data: *const c_char) -> i32 {
    || -> HlsResult<i32> {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        let data = unsafe { CStr::from_ptr(data) }.to_bytes();
        let data = json::from_bytes(data)?;
        req.set_json(data);
        Ok(0)
    }().unwrap_or(-1)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_set_bytes(req: *mut ScReq, bytes: *const c_char, len: u32) -> i32 {
    || -> HlsResult<i32> {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        let bytes = unsafe { slice::from_raw_parts(bytes as *const u8, len as usize) }.to_vec();
        req.set_bytes(bytes);
        Ok(0)
    }().unwrap_or(-1)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_set_text(req: *mut ScReq, text: *const c_char) -> i32 {
    || -> HlsResult<i32> {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        let text = unsafe { CStr::from_ptr(text) }.to_str()?;
        req.set_text(text);
        Ok(0)
    }().unwrap_or(-1)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_set_timeout(req: *mut ScReq, timeout: *const c_char) -> i32 {
    || -> HlsResult<i32> {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        let timeout = unsafe { CStr::from_ptr(timeout) }.to_bytes();
        let data = json::from_bytes(timeout)?;
        let timeout = Timeout::try_from(data)?;
        req.set_timeout(timeout);
        Ok(0)
    }().unwrap_or(-1)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_set_cookie(req: *mut ScReq, cookie: *const c_char) -> i32 {
    || -> HlsResult<i32> {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        let cookie = unsafe { CStr::from_ptr(cookie) }.to_str()?;
        req.header_mut().set_cookie(cookie)?;
        Ok(0)
    }().unwrap_or(-1)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_add_cookie(req: *mut ScReq, name: *const c_char, value: *const c_char) -> i32 {
    || -> HlsResult<i32> {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        let name = unsafe { CStr::from_ptr(name) }.to_str()?;
        let value = unsafe { CStr::from_ptr(value) }.to_str()?;
        let cookie = Cookie::new_cookie(name, value);
        req.header_mut().add_cookie(cookie);
        Ok(0)
    }().unwrap_or(-1)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ScReq_stream_io(req: *mut ScReq, method: Method) -> *mut c_char {
    let res = catch_unwind(AssertUnwindSafe(|| {
        let res = || -> HlsResult<String> {
            let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
            req.header_mut().set_method(method);
            let mut resp = req.stream_io()?;
            let res = json::object! {
            "header":resp.header(),
            "body":hex::encode(resp.decode_body()?.as_bytes()?),
        };
            Ok(hex::encode(res.dump()))
        };
        match res() {
            Ok(res) => {
                // println!("res: {}", res.len());
                CString::new(res).unwrap().into_raw()
            }
            Err(e) => {
                // println!("{}", e.to_string());
                CString::new(hex::encode(e.to_string())).unwrap().into_raw()
            }
        }
    }));
    res.unwrap_or_else(|_| CString::new(hex::encode("程序panic")).unwrap().into_raw())
}
#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_reconnect(req: *mut ScReq) -> i32 {
    || -> HlsResult<i32> {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        req.re_conn()?;
        Ok(0)
    }().unwrap_or(-1)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn ScReq_drop(req: *mut ScReq) {
    if req.is_null() { return; }
    let req = unsafe { Box::from_raw(req) };
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
pub extern "C" fn ScReq_set_callback(req: *mut ScReq, callback: Callback) -> i32 {
    || -> HlsResult<i32> {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        req.set_callback(move |bs| {
            callback(bs.as_ptr() as *const c_char, bs.len() as u32);
            Ok(())
        });
        Ok(0)
    }().unwrap_or(-1)
}












