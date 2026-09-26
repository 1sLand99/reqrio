#[cfg(debug_assertions)]
use std::fmt::Debug;

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct StatusType(u8);

impl StatusType {
    pub const OCSP: StatusType = StatusType::new(0x1);

    pub const fn new(value: u8) -> StatusType {
        StatusType(value)
    }
}

#[cfg(debug_assertions)]
impl Debug for StatusType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            StatusType::OCSP => write!(f, "OCSP(0x{:02x})", self.0),
            _ => write!(f, "Unknown(0x{:02x})", self.0),
        }
    }
}

#[repr(C)]
#[derive(Clone)]
#[cfg_attr(debug_assertions, derive(Debug))]
pub struct StatusRequest {
    typ: StatusType,
    resp_id_len: u16,
    req_ext_len: u16,
}

impl StatusRequest {
    pub const OCSP: StatusRequest = StatusRequest { typ: StatusType::OCSP, resp_id_len: 0, req_ext_len: 0 };
}