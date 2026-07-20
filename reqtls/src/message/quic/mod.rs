mod frame;

use crate::Buf;
pub(crate) use frame::FrameType;


#[derive(Default, Copy, Clone, Debug)]
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
pub(crate) struct QUICPacket<'a> {
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
    pub(crate) fn aad(&self) -> &[u8] {
        &self.hdr_raw[..self.hdr_len]
    }
}


#[cfg(test)]
mod tests {
    #[test]
    fn test_en_payload() {}
}