use super::req::{Callback, CONNECTIONS};
use crate::error::HlsResult;
use std::ffi::{c_char, CStr};
use std::thread::sleep;
use std::time::Duration;

#[unsafe(no_mangle)]
pub extern "system" fn wss_h1_io(id: i32, context: *const c_char, callback: Callback) {
    || -> HlsResult<()>{
        let mut conns = CONNECTIONS.lock()?;
        let mut req = conns.remove(&id).ok_or("id not found")?;
        drop(conns);
        let context = unsafe { CStr::from_ptr(context) }.to_bytes();
        loop {
            let res = || -> HlsResult<()>{
                let resp = req.h1_io(context.to_vec())?;
                println!("{}", resp.raw_string());
                req.handle_websocket(|frame| {
                    let payload = frame.payload().as_bytes();
                    callback(payload.as_ptr() as *const c_char, payload.len() as u32);
                    Ok(())
                })
            }();
            match res {
                Ok(_) => break Ok(()),
                Err(e) => if e.to_string().to_lowercase().contains("close") || e.to_string().contains("中止了") {
                    req.re_conn()?;
                }
            }
            sleep(Duration::from_millis(100));
        }
    }().unwrap_or_else(|e| println!("{}", e.to_string()));
}


#[cfg(test)]
mod tests {
    use crate::export::req::{init_http, set_url};
    use crate::export::wss::wss_h1_io;
    use std::ffi::{c_char, CStr, CString};

    extern "C" fn callback(data: *const c_char, len: u32) {
        let data = unsafe { CStr::from_ptr(data) }.to_bytes();
        println!("{}", data.len());
    }

    #[test]
    fn test_wss_h1_io() {
        let hid = init_http();
        let url = CString::new("https://poe.game.qq.com/").unwrap();
        set_url(hid, url.as_ptr());
        let context = CString::new(r#"GET wss://poe.game.qq.com/api/trade2/live/poe2/%E7%93%A6%E5%B0%94%E7%9A%84%E5%AE%BF%E5%91%BD/32Y6Wjkc5 HTTP/1.1
Host: poe.game.qq.com
Connection: Upgrade
Pragma: no-cache
Cache-Control: no-cache
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0
Upgrade: websocket
Origin: https://poe.game.qq.com
Sec-WebSocket-Version: 13
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
Cookie: pac_uid=0_NattYaCs7NNmH; omgid=0_NattYaCs7NNmH; _qimei_uuid42=19c1f11150d1000f92fe16d850a9c40cf94ef1d39f; _qimei_fingerprint=f3dc39297e432b1f08da57e9904a8f52; _qimei_q36=; _qimei_h38=a549811f92fe16d850a9c40c02000006b19c1f; _qpsvr_localtk=0.2296543129537577; RK=WPZCq/wl3I; ptcz=c338dead622f05f0d8467ac10589e7e45326b81d67ff476b9643f933cfdc644a; eas_sid=M1b7q677w9D5R5P2L8x5g4p313; eas_entry=https%3A%2F%2Fgraph.qq.com%2F; POESESSID=939e23af876572a0b2852b2e183e20cc
Sec-WebSocket-Key: Y/3ZjeJohL99ku1nNT2WEQ==
Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits

"#.replace("\n", "\r\n")).unwrap();
        wss_h1_io(hid, context.as_ptr(), callback);
    }
}