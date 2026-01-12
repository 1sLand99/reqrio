use crate::error::HlsResult;
use std::ffi::{c_char, CStr, CString};
use std::ptr::null_mut;
use crate::{json, HlsError, Proxy, ScReq, Url, WebSocket, WebSocketBuilder, WsFrame, WsOpcode};

#[unsafe(no_mangle)]
pub extern "system" fn build_ws() -> *mut WebSocketBuilder<ScReq> {
    Box::into_raw(Box::new(WebSocket::sync_build()))
}

#[unsafe(no_mangle)]
pub extern "system" fn ws_add_header(builder: *mut WebSocketBuilder<ScReq>, name: *const c_char, value: *const c_char) -> i32 {
    || -> HlsResult<i32>{
        let builder = unsafe { builder.as_mut().ok_or(HlsError::NullPointer) }?;
        let name = unsafe { CStr::from_ptr(name) }.to_str()?;
        let value = unsafe { CStr::from_ptr(value) }.to_str()?;
        builder.add_header(name, value)?;
        Ok(0)
    }().unwrap_or(-1)
}

#[unsafe(no_mangle)]
pub extern "system" fn ws_set_proxy(builder: *mut WebSocketBuilder<ScReq>, proxy: *const c_char) -> i32 {
    || -> HlsResult<i32>{
        let builder = unsafe { builder.as_mut().ok_or(HlsError::NullPointer) }?;
        let proxy = unsafe { CStr::from_ptr(proxy) }.to_str()?;
        let url = Url::try_from(proxy)?;
        builder.set_proxy(Proxy::HttpPlain(url.addr().clone()));
        Ok(0)
    }().unwrap_or(-1)
}

#[unsafe(no_mangle)]
pub extern "system" fn ws_set_url(builder: *mut WebSocketBuilder<ScReq>, url: *const c_char) -> i32 {
    || -> HlsResult<i32>{
        let builder = unsafe { builder.as_mut().ok_or(HlsError::NullPointer) }?;
        let url = unsafe { CStr::from_ptr(url) }.to_str()?;
        builder.set_url(url)?;
        Ok(0)
    }().unwrap_or(-1)
}

#[unsafe(no_mangle)]
pub extern "system" fn ws_set_uri(builder: *mut WebSocketBuilder<ScReq>, uri: *const c_char) -> i32 {
    || -> HlsResult<i32>{
        let builder = unsafe { builder.as_mut().ok_or(HlsError::NullPointer) }?;
        let uri = unsafe { CStr::from_ptr(uri) }.to_str()?;
        builder.set_uri(uri)?;
        Ok(0)
    }().unwrap_or(-1)
}

#[unsafe(no_mangle)]
pub extern "system" fn open_ws(builder: *mut WebSocketBuilder<ScReq>) -> *mut WebSocket {
    || -> HlsResult<*mut WebSocket>{
        let builder = unsafe { Box::from_raw(builder) };
        let ws = builder.build()?;
        Ok(Box::into_raw(Box::new(ws)))
    }().unwrap_or_else(|e| {
        println!("{}", e);
        null_mut()
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn open_ws_raw(url: *const c_char, context: *const c_char) -> *mut WebSocket {
    || -> HlsResult<*mut WebSocket>{
        let url = unsafe { CStr::from_ptr(url) }.to_str()?;
        let context = unsafe { CStr::from_ptr(context) }.to_bytes();
        let ws = WebSocket::open_raw(url, context)?;
        Ok(Box::into_raw(Box::new(ws)))
    }().unwrap_or(null_mut())
}

#[unsafe(no_mangle)]
pub extern "system" fn ws_read(websocket: *mut WebSocket) -> *mut c_char {
    || -> HlsResult<*mut c_char>{
        let websocket = unsafe { websocket.as_mut() }.ok_or(HlsError::NullPointer)?;
        let frame = websocket.read_frame()?;
        let res = json::object! {
            "opcode":*frame.frame_type().op_code() as u8,
            "payload":frame.payload().as_bytes(),
        };
        let res = CString::new(res.dump()).unwrap();
        Ok(res.into_raw())
    }().unwrap_or_else(|e| {
        let res = CString::new(e.to_string()).unwrap();
        res.into_raw()
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn ws_write(websocket: *mut WebSocket, op_code: i32, mask: bool, payload: *const c_char) -> i32 {
    || -> HlsResult<i32> {
        let websocket = unsafe { websocket.as_mut() }.ok_or(HlsError::NullPointer)?;
        let payload = unsafe { CStr::from_ptr(payload) }.to_bytes();
        let opcode = WsOpcode::from_u8(op_code as u8).ok_or("opcode unknow")?;
        let frame = WsFrame::new_frame(opcode, mask, payload);
        websocket.write_frame(frame)?;
        Ok(0)
    }().unwrap_or(-1)
}

#[unsafe(no_mangle)]
pub extern "system" fn ws_close(websocket: *mut WebSocket) {
    let websocket = unsafe { Box::from_raw(websocket) };
    let _ = websocket.shutdown();
}