use std::ptr;
use crate::error::HlsResult;
use crate::HlsError;
use crate::packet::ws::Marker;

pub struct WsPayload {
    len: usize,
    mask: [u8; 4],
    payload: Vec<u8>,
}

impl WsPayload {
    pub fn new() -> WsPayload {
        WsPayload {
            len: 0,
            mask: [43, 34, 56, 23],
            payload: vec![],
        }
    }

    pub(crate) fn copy_payload(&mut self, payload: &[u8], masker: &Marker) {
        self.payload.reserve(payload.len());
        let dst = self.payload.as_mut_ptr();
        unsafe { ptr::copy_nonoverlapping(payload.as_ptr(), dst, payload.len()) };
        unsafe { self.payload.set_len(payload.len()); }
        if masker.mask {
            self.payload.iter_mut().enumerate().for_each(|(i, b)| *b ^= self.mask[i % 4])
        }
        self.len = payload.len();
    }

    pub fn from_bytes(masker: &Marker, bytes: &[u8]) -> HlsResult<WsPayload> {
        let mut res = WsPayload::new();
        match masker.len_code {
            127 => {
                if bytes.len() < 8 { return Err(HlsError::DataTooShort); }
                res.len = u64::from_be_bytes(bytes[..8].try_into()?) as usize;
                if masker.mask {
                    if bytes.len() < res.len + 4 + 8 { return Err(HlsError::DataTooShort); }
                    res.mask.copy_from_slice(&bytes[8..12]);
                    res.copy_payload(&bytes[12..12 + res.len], masker);
                } else {
                    if bytes.len() < res.len + 8 { return Err(HlsError::DataTooShort); }
                    res.copy_payload(&bytes[8..8 + res.len], masker);
                }
            }
            126 => {
                res.len = u16::from_be_bytes(bytes[..2].try_into()?) as usize;
                if masker.mask {
                    if bytes.len() < res.len + 4 + 2 { return Err(HlsError::DataTooShort); }
                    res.mask.copy_from_slice(&bytes[2..6]);
                    res.copy_payload(&bytes[6..6 + res.len], masker);
                } else {
                    if bytes.len() < res.len + 2 { return Err(HlsError::DataTooShort); }
                    res.copy_payload(&bytes[2..2 + res.len], masker);
                }
            }
            _ => {
                res.len = masker.len_code as usize;
                if masker.mask {
                    if bytes.len() < res.len + 4 { return Err(HlsError::DataTooShort); }
                    res.mask.copy_from_slice(&bytes[..4]);
                    res.copy_payload(&bytes[4..4 + res.len], masker);
                } else {
                    if bytes.len() < res.len { return Err(HlsError::DataTooShort); }
                    res.copy_payload(&bytes[..res.len], masker);
                }
            }
        }
        Ok(res)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.payload
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn to_bytes(self, masker: &Marker) -> Vec<u8> {
        let mut res = if masker.mask { self.mask.to_vec() } else { vec![] };
        res.extend(self.payload);
        res
    }
}
