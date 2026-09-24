#[cfg(debug_assertions)]
use std::fmt::{Debug, Formatter};
use std::ptr::null;
use std::slice;

#[repr(C)]
#[derive(Default, Clone)]
pub struct ServerName {
    typ: u8,
    len: u16,
    ptr: *const u8,
}

impl ServerName {
    pub const HOSTNAME: ServerName = ServerName { typ: 0, len: 0, ptr: null() };

    pub fn new_sni(sni: &str) -> ServerName {
        ServerName {
            typ: 0,
            len: sni.len() as u16,
            ptr: sni.as_ptr(),
        }
    }
}

unsafe impl Sync for ServerName {}
unsafe impl Send for ServerName {}

#[cfg(debug_assertions)]
impl Debug for ServerName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut debug_struct = f.debug_struct("ServerName");
        if self.typ == 0x0 {
            debug_struct.field("type", &"Hostname");
            let hostname = unsafe { slice::from_raw_parts(self.ptr, self.len as usize) };
            debug_struct.field("value", &std::str::from_utf8(hostname).unwrap());
        }
        debug_struct.finish()
    }
}



