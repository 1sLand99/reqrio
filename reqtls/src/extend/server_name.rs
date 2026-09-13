use std::fmt::{Debug, Formatter};
use std::os::raw::c_void;
use std::ptr::null;
use std::slice;
use crate::{BufferError, Reader, Writer};

#[derive(Debug, Clone)]
pub enum SNType<'a> {
    HostName(&'a str),
}

impl<'a> SNType<'a> {
    pub const HOST_NAME: u8 = 0x0;

    pub fn len(&self) -> usize {
        match self {
            SNType::HostName(name) => 3 + name.len()
        }
    }

    pub fn write_to(&self, writer: &mut Writer) -> Result<(), BufferError> {
        match self {
            SNType::HostName(name) => {
                writer.write_u8(SNType::HOST_NAME)?;
                writer.write_u16(name.len() as u16)?;
                writer.write_slice(name.as_bytes())?;
            }
        }
        Ok(())
    }
}

#[repr(C)]
#[derive(Default)]
struct Hostname {
    len: u16,
    ptr: *const u8,
}

#[cfg(debug_assertions)]
impl Debug for Hostname {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut struct_debug = f.debug_struct("Hostname");
        struct_debug.field("len", &self.len);
        let slice = unsafe { slice::from_raw_parts(self.ptr, self.len as usize) };
        let hostname = std::str::from_utf8(slice).unwrap_or("");
        struct_debug.field("ptr", &hostname);
        struct_debug.finish()
    }
}


#[repr(C)]
#[derive(Default)]
pub struct ServerName {
    typ: u8,
    ptr: *const c_void,
}

impl ServerName {
    pub const HOSTNAME: ServerName = ServerName { typ: 0, ptr: null() };
}

#[cfg(debug_assertions)]
impl Debug for ServerName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut debug_struct = f.debug_struct("ServerName");
        debug_struct.field("type", &self.typ);
        if self.typ == 0x0 {
            let mut reader = Reader::from_ptr(self.ptr as *const u8, usize::MAX);
            let hostname = Hostname {
                len: reader.read_u16().unwrap(),
                ptr: reader.unread_ptr(),
            };
            debug_struct.field("hostname", &hostname);
        }
        debug_struct.finish()
    }
}



