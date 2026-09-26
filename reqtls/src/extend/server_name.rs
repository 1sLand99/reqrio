use crate::Buf;
#[cfg(debug_assertions)]
use std::fmt::{Debug, Formatter};

#[repr(C)]
#[derive(Default, Clone)]
pub struct ServerName {
    typ: u8,
    value: Buf<'static>,
}

impl ServerName {
    pub const HOSTNAME: ServerName = ServerName { typ: 0, value: Buf::new_ref(&[]) };

    pub fn nullptr() -> ServerName {
        ServerName {
            typ: 0,
            value: Buf::new_c(),
        }
    }
}

#[cfg(debug_assertions)]
impl Debug for ServerName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut debug_struct = f.debug_struct("ServerName");
        if self.typ == 0x0 {
            debug_struct.field("type", &"Hostname");
            debug_struct.field("value", &std::str::from_utf8(self.value.as_slice()).unwrap());
        }
        debug_struct.finish()
    }
}



