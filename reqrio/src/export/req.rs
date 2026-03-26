use crate::error::HlsResult;
use crate::time::timeout::Timeout;
use crate::{json, Cookie, HlsError, Method, Proxy, ReqExt, ScReq, ALPN};
use crate::{Application, ContentType, Fingerprint};
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
pub extern "system" fn ScReq_set_verify(req: *mut ScReq, verify: bool) -> i32 {
    || -> HlsResult<i32> {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        req.set_verify(verify);
        Ok(0)
    }().unwrap_or(-1)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_set_redirect(req: *mut ScReq, redirect: bool) -> i32 {
    || -> HlsResult<i32> {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        req.set_auto_redirect(redirect);
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
pub extern "system" fn ScReq_set_bytes(req: *mut ScReq, bytes: *const u8, len: u32, context_type: *const c_char) -> i32 {
    || -> HlsResult<i32> {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        let bytes = unsafe { slice::from_raw_parts(bytes, len as usize) };
        let ct = unsafe { CStr::from_ptr(context_type) }.to_str()?;
        let ct = ContentType::try_from(ct)?;
        if let ContentType::Application(ref application) = ct {
            match application {
                Application::Json => {
                    let data = json::from_bytes(bytes)?;
                    req.set_json(data);
                }
                Application::XWwwFormUrlencoded => {
                    let data = json::from_bytes(bytes)?;
                    req.set_data(data);
                }
                _ => req.set_bytes(bytes, ct)
            }
        } else { req.set_bytes(bytes, ct) }
        Ok(0)
    }().unwrap_or(-1)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn ScReq_set_context_type(req: *mut ScReq, context_type: *const c_char) -> i32 {
    || -> HlsResult<i32> {
        let req = unsafe { req.as_mut().ok_or(HlsError::NullPointer) }?;
        let context_type = unsafe { CStr::from_ptr(context_type) }.to_str()?;
        let context_type = ContentType::try_from(context_type)?;
        req.header_mut().set_content_type(context_type);
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












