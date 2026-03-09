use crate::error::HlsResult;
use crate::HlsError;

#[derive(Copy, Clone)]
pub enum WsOpcode {
    CONTINUATION = 0x0,
    TEXT = 0x1,
    BINARY = 0x2,
    CLOSE = 0x8,
    PING = 0x9,
    PONG = 0xA,
}

impl WsOpcode {
    pub fn from_u8(opcode: u8) -> Option<WsOpcode> {
        match opcode {
            0 => Some(WsOpcode::CONTINUATION),
            1 => Some(WsOpcode::TEXT),
            2 => Some(WsOpcode::BINARY),
            8 => Some(WsOpcode::CLOSE),
            9 => Some(WsOpcode::PING),
            0xA => Some(WsOpcode::PONG),
            _ => None,
        }
    }
}

///```text
///     0     1      2     3      4   5   6   7
/// +-----+------+------+------+---+---+---+---+
/// | fin | rsv1 | rsv2 | rsv3 |     opcode    |
/// +-----+------+------+------+---------------+
/// ```
pub struct WsFrameType {
    fin: bool,
    rsv1: bool,
    rsv2: bool,
    rsv3: bool,
    opcode: WsOpcode,
}

impl WsFrameType {
    pub fn new() -> WsFrameType {
        WsFrameType {
            fin: false,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: WsOpcode::TEXT,
        }
    }
    pub fn is_fin(&self) -> bool {
        self.fin
    }

    pub fn set_fin(&mut self, fin: bool) {
        self.fin = fin;
    }

    pub fn set_opcode(&mut self, opcode: WsOpcode) {
        self.opcode = opcode;
    }

    pub(crate) fn from_u8(value: u8) -> HlsResult<WsFrameType> {
        let mut res = WsFrameType::new();
        res.fin = value & 0x80 == 0x80;
        res.rsv1 = value & 0x40 == 0x40;
        res.rsv2 = value & 0x20 == 0x20;
        res.rsv3 = value & 0x10 == 0x10;
        res.opcode = WsOpcode::from_u8(value & 0xF).ok_or(HlsError::WsFrameTypeNone)?;
        Ok(res)
    }

    pub fn op_code(&self) -> &WsOpcode {
        &self.opcode
    }

    pub fn to_u8(self) -> u8 {
        let mut res = 0u8;
        if self.fin { res |= 0x80 }
        if self.rsv1 { res |= 0x40 }
        if self.rsv2 { res |= 0x20 }
        if self.rsv3 { res |= 0x10 }
        res |= self.opcode as u8;
        res
    }
}
