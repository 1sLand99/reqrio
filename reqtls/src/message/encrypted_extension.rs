use crate::error::RlsResult;
use crate::{u24, Reader};
use std::os::raw::c_void;

#[repr(C)]
#[cfg_attr(debug_assertions, derive(Debug))]
pub struct EncryptedExtension {
    pub(crate) len: u24,
    pub(crate) ext_len: u16,
    pub(crate) extension: *const c_void,
}

impl EncryptedExtension {
    pub fn from_reader(reader: &mut Reader) -> RlsResult<EncryptedExtension> {
        let len = reader.read_u24()?;
        let ext_len = reader.read_u16()?;
        Ok(EncryptedExtension {
            len,
            ext_len,
            extension: reader.read_ptr(ext_len as usize)? as *const c_void,
        })
    }
}