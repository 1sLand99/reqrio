use super::super::version::Version;
use crate::*;
use std::os::raw::c_void;
use std::ptr::null;
use std::slice;

#[repr(C)]
#[cfg_attr(debug_assertions, derive(Debug))]
pub struct ClientHello {
    pub(crate) len: u24,
    pub(crate) version: Version,
    pub(crate) random: *const u8,
    pub(crate) session_id_len: u8,
    pub(crate) session_id: *const u8,
    pub(crate) cipher_suites_len: u16,
    pub(crate) cipher_suites: *const c_void,
    pub(crate) compress_method_len: u8,
    pub(crate) compress_method: *const u8,
    pub(crate) extend_len: u16,
    pub(crate) extensions: *const c_void,
}

impl ClientHello {
    pub fn from_reader(reader: &mut Reader) -> Result<ClientHello, BufferError> {
        let mut client_hello = ClientHello {
            len: reader.read_u24()?,
            version: Version::new(reader.read_u16()?),
            random: reader.read_ptr(32)?,
            session_id_len: reader.read_u8()?,
            session_id: null(),
            cipher_suites_len: 0,
            cipher_suites: null(),
            compress_method_len: 0,
            compress_method: null(),
            extend_len: 0,
            extensions: null(),
        };
        client_hello.session_id = reader.read_ptr(client_hello.session_id_len as usize)?;
        client_hello.cipher_suites_len = reader.read_u16()?;
        client_hello.cipher_suites = reader.read_ptr(client_hello.cipher_suites_len as usize)? as *const c_void;
        client_hello.compress_method_len = reader.read_u8()?;
        client_hello.compress_method = reader.read_ptr(client_hello.compress_method_len as usize)?;
        client_hello.extend_len = reader.read_u16()?;
        client_hello.extensions = reader.read_ptr(client_hello.extend_len as usize)? as *const c_void;
        Ok(client_hello)
    }

    pub fn random(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.random, 32) }
    }
}