mod frame;

use crate::Buf;
pub use frame::FrameType;


#[derive(Default, Copy, Clone, Debug, PartialEq)]
pub enum PacketType {
    #[default]
    Initial = 0
}

impl From<u8> for PacketType {
    fn from(value: u8) -> Self {
        match value {
            0 => PacketType::Initial,
            _ => unreachable!(),
        }
    }
}


#[derive(Default, Debug)]
pub struct QUICFlag {
    long_header: bool,
    fixed_bit: bool,
    packet_type: PacketType,
    reserved: u8,
    num_len: u8,
}

impl QUICFlag {
    pub fn from_u8(v: u8) -> QUICFlag {
        QUICFlag {
            long_header: v & 0x80 == 0x80,
            fixed_bit: v & 0x40 == 0x40,
            packet_type: ((v & 0x30) >> 4).into(),
            reserved: v & 0xc >> 2,
            num_len: (v & 3) + 1,
        }
    }

    pub fn encode(&self) -> u8 {
        let mut v = 0;
        if self.long_header {
            v |= 0x80;
        }
        if self.fixed_bit {
            v |= 0x40;
        }
        v |= (self.packet_type as u8) << 4;
        v |= self.reserved << 2;
        match self.num_len {
            1 => v |= 0b00,
            2 => v |= 0b01,
            4 => v |= 0b10,
            8 => v |= 0b11,
            _ => unreachable!(),
        }
        v
    }

    pub fn num_len(&self) -> usize {
        self.num_len as usize
    }

    pub fn packet_type(&self) -> PacketType {
        self.packet_type
    }

    pub fn is_long_header(&self) -> bool {
        self.long_header
    }
}

#[derive(Debug)]
pub struct QUICPacket<'a> {
    pub(crate) flag: QUICFlag,
    pub(crate) ver: u32,
    pub(crate) dc_id: Buf<'a>,
    pub(crate) sc_id: Buf<'a>,
    pub(crate) token: Buf<'a>,
    pub(crate) len: usize,
    pub(crate) num: u64,
    pub(crate) payload: Buf<'a>,

    pub(crate) hdr_raw: [u8; 30],
    pub(crate) hdr_len: usize,
}

impl<'a> Default for QUICPacket<'a> {
    fn default() -> Self {
        QUICPacket {
            flag: QUICFlag::default(),
            ver: 0,
            dc_id: Buf::Ref(&[]),
            sc_id: Buf::Ref(&[]),
            token: Buf::Ref(&[]),
            len: 0,
            num: 0,
            payload: Buf::Ref(&[]),
            hdr_raw: [0; 30],
            hdr_len: 0,
        }
    }
}

impl<'a> QUICPacket<'a> {
    pub fn new_initial(num: u64, pd_len: usize) -> Self {
        let num_len = crate::quic::variant_len(num as usize);
        QUICPacket {
            flag: QUICFlag {
                long_header: true,
                fixed_bit: true,
                packet_type: PacketType::Initial,
                reserved: 0,
                num_len: num_len as u8,
            },
            ver: 1,
            len: num_len + pd_len + 16,
            ..Default::default()
        }
    }

    pub(crate) fn aad(&self) -> &[u8] {
        &self.hdr_raw[..self.hdr_len]
    }

    pub fn hdr_len(&self) -> usize {
        self.hdr_len
    }

    pub fn flag(&self) -> &QUICFlag {
        &self.flag
    }

    pub fn set_hdr_len(&mut self, dcid_len: usize, scid_len: usize) {
        self.hdr_len = 1 + 4 + 1 + dcid_len + 1 + scid_len + crate::quic::variant_len(self.token.len())
            + self.token.len() + crate::quic::variant_len(self.len) + self.flag.num_len as usize;
    }
}


#[cfg(test)]
mod tests {
    #[test]
    fn test_en_payload() {}
}