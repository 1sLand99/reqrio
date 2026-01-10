pub use payload::WsPayload;
pub use typ::{WsFrameType, WsOpcode};


mod payload;
mod typ;

use crate::error::HlsResult;
use crate::{Buffer, HlsError};


pub struct Marker {
    mask: bool,
    len_code: u8,
}

impl Marker {
    pub fn new() -> Marker {
        Marker {
            mask: false,
            len_code: 0,
        }
    }

    pub fn from_u8(value: u8) -> Marker {
        let mut res = Marker::new();
        res.mask = value & 0x80 == 0x80;
        res.len_code = value & 0x7f;
        res
    }

    pub fn to_u8(self, len: usize) -> u8 {
        let mut res = 0u8;
        if self.mask { res |= 0x80 }
        match len {
            ..126 => res |= len as u8,
            126..0xFFFF => res |= 126,
            0xFFFF.. => res |= 127,
        }
        res
    }
}


pub struct WsFrame {
    typ: WsFrameType,
    masker: Marker,
    payload: WsPayload,
}

impl WsFrame {
    pub fn new() -> WsFrame {
        WsFrame {
            typ: WsFrameType::new(),
            masker: Marker::new(),
            payload: WsPayload::new(),
        }
    }

    pub fn new_pong(mask: bool, payload: &[u8]) -> WsFrame {
        let mut res = WsFrame::new();
        res.typ.set_opcode(WsOpcode::PONG);
        res.typ.set_fin(true);
        res.masker.mask = mask;
        res.payload.copy_payload(payload, &res.masker);
        res
    }

    pub fn new_binary(mask: bool, payload: &[u8]) -> WsFrame {
        let mut res = WsFrame::new();
        res.typ.set_opcode(WsOpcode::BINARY);
        res.typ.set_fin(true);
        res.masker.mask = mask;
        res.payload.copy_payload(payload, &res.masker);
        res
    }

    pub fn new_text(mask: bool, payload: impl AsRef<str>) -> WsFrame {
        let mut res = WsFrame::new();
        res.typ.set_opcode(WsOpcode::TEXT);
        res.typ.set_fin(true);
        res.masker.mask = mask;
        res.payload.copy_payload(payload.as_ref().as_bytes(), &res.masker);
        res
    }

    pub fn len(&self) -> usize {
        let mut len = 2;
        if self.masker.mask {
            len += 4;
        }
        len += match self.masker.len_code {
            127 => 8,
            126 => 2,
            _ => 0
        };
        len += self.payload.len();
        len
    }

    pub fn from_buffer(buffer: &mut Buffer) -> HlsResult<WsFrame> {
        if buffer.len() < 2 { return Err(HlsError::InvalidHeadSize); }
        let mut res = WsFrame::new();
        res.typ = WsFrameType::from_u8(buffer[0])?;
        res.masker = Marker::from_u8(buffer[1]);
        res.payload = WsPayload::from_bytes(&res.masker, &buffer.filled()[2..])?;
        buffer.copy_within(res.len()..buffer.len(), 0);
        buffer.set_len(buffer.len() - res.len());
        Ok(res)
    }

    pub fn payload(&self) -> &WsPayload {
        &self.payload
    }

    pub fn frame_type(&self) -> &WsFrameType {
        &self.typ
    }

    pub fn to_bytes(self) -> Vec<u8> {
        let payload_len = self.payload.len();
        let payload = self.payload.to_bytes(&self.masker);
        let mut res = vec![self.typ.to_u8(), self.masker.to_u8(payload_len)];
        res.extend(payload);
        res
    }
}