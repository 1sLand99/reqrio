#[derive(Copy, Clone)]
pub enum WsOpcode {
    CONTINUATION = 0x0,
    TEXT = 0x1,
    BINARY = 0x2,
    CLOSE = 0x8,
    PING = 0x9,
    PONG = 0xA,
}

impl From<u8> for WsOpcode {
    fn from(opcode: u8) -> Self {
        match opcode {
            0 => WsOpcode::CONTINUATION,
            1 => WsOpcode::TEXT,
            2 => WsOpcode::BINARY,
            8 => WsOpcode::CLOSE,
            9 => WsOpcode::PING,
            0xA => WsOpcode::PONG,
            _ => unreachable!(),
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
    pub fn new(fin: bool, opcode: WsOpcode) -> WsFrameType {
        WsFrameType {
            fin,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode,
        }
    }
    pub fn is_fin(&self) -> bool {
        self.fin
    }

    pub fn op_code(&self) -> &WsOpcode {
        &self.opcode
    }

    pub fn encode(self) -> u8 {
        let mut res = 0u8;
        if self.fin { res |= 0x80 }
        if self.rsv1 { res |= 0x40 }
        if self.rsv2 { res |= 0x20 }
        if self.rsv3 { res |= 0x10 }
        res |= self.opcode as u8;
        res
    }
}

impl From<u8> for WsFrameType {
    fn from(value: u8) -> WsFrameType {
        WsFrameType {
            fin: value & 0x80 == 0x80,
            rsv1: value & 0x40 == 0x40,
            rsv2: value & 0x20 == 0x20,
            rsv3: value & 0x10 == 0x10,
            opcode: (value & 0xF).into(),
        }
    }
}
