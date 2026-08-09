mod frame;

use crate::{Buf, Buffer, BufferError, ReadExt, Reader, WriteExt};
pub use frame::{QUICFrame, QUICFrameFlag, AckRange};


#[derive(Default, Copy, Clone, Debug, PartialEq)]
pub enum PacketType {
    #[default]
    Initial = 0,
    Handshake = 2,
    ShortHeader,
}

impl From<u8> for PacketType {
    fn from(value: u8) -> Self {
        match value {
            0 => PacketType::Initial,
            2 => PacketType::Handshake,
            _ => unreachable!(),
        }
    }
}


#[derive(Default, Debug, Copy, Clone)]
pub struct QUICFlag {
    long_header: bool,
    fixed_bit: bool,
    spin_bit: bool,
    packet_type: PacketType,
    reserved: u8,
    key_phase: bool,
    num_len: u8,
}

impl QUICFlag {
    pub fn from_raw(v: u8) -> QUICFlag {
        let mut flag = QUICFlag {
            long_header: v & 0x80 == 0x80,
            fixed_bit: v & 0x40 == 0x40,
            spin_bit: false,
            packet_type: PacketType::ShortHeader,
            reserved: 0,
            key_phase: false,
            num_len: 0,
        };
        if flag.long_header {
            flag.packet_type = ((v & 0x30) >> 4).into();
        } else {
            flag.spin_bit = (v & 0x20) == 0x20;
        }
        flag
    }

    fn decode(&mut self, v: u8) {
        if self.long_header {
            self.reserved = v & 0xc >> 2;
        } else {
            self.reserved = (v >> 3) & 3;
            self.key_phase = v & 4 == 4;
        }
        self.num_len = (v & 3) + 1;
    }

    pub fn encode(&self) -> u8 {
        let mut v = 0;
        if self.long_header {
            v |= 0x80;
        }
        if self.fixed_bit {
            v |= 0x40;
        }
        if self.long_header {
            v |= (self.packet_type as u8) << 4;
            v |= self.reserved << 2;
        } else {
            if self.spin_bit {
                v |= 0x20;
            }
            v |= self.reserved << 3;
            if self.key_phase {
                v |= 4;
            }
        }
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
    len: usize,
    pub(crate) pn_offset: usize,
    pub(crate) num: u64,
    pub(crate) payload: Buf<'a>,

    pub(crate) hdr_raw: [u8; 30],
    pub(crate) hdr_len: usize,
    pub(crate) padding: usize,
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
            pn_offset: 0,
            num: 0,
            payload: Buf::Ref(&[]),
            hdr_raw: [0; 30],
            hdr_len: 0,
            padding: 0,
        }
    }
}

impl<'a> QUICPacket<'a> {
    pub fn new_long(pty: PacketType, num: u64, pd_len: usize, dcid: &'a [u8]) -> Self {
        let num_len = crate::quic::variant_len(num as usize);
        let (len, padding) = if pd_len + num_len + 16 >= 1232 {
            (pd_len + num_len + 16, 0)
        } else { (1232, 1232 - pd_len - num_len - 16) };
        QUICPacket {
            flag: QUICFlag {
                long_header: true,
                fixed_bit: true,
                spin_bit: false,
                packet_type: pty,
                reserved: 0,
                key_phase: false,
                num_len: num_len as u8,
            },
            ver: 1,
            len,
            num,
            padding,
            dc_id: Buf::Ref(dcid),
            ..Default::default()
        }
    }

    pub fn new_short(pty: PacketType, num: u64, pd_len: usize, dcid: &'a [u8]) -> Self {
        let num_len = crate::quic::variant_len(num as usize);
        QUICPacket {
            flag: QUICFlag {
                long_header: false,
                fixed_bit: true,
                spin_bit: false,
                packet_type: pty,
                reserved: 0,
                key_phase: false,
                num_len: num_len as u8,
            },
            ver: 1,
            len: pd_len + num_len + 16,
            num,
            padding: 0,
            dc_id: Buf::Ref(dcid),
            ..Default::default()
        }
    }

    pub fn new_ack(flag: QUICFlag, dc_id: &'a [u8], num: u64, pd_len: usize) -> Self {
        let num_len = crate::quic::variant_len(num as usize);
        let len = pd_len + num_len + 16;
        QUICPacket {
            flag: QUICFlag {
                long_header: flag.long_header,
                fixed_bit: flag.fixed_bit,
                spin_bit: false,
                packet_type: flag.packet_type,
                reserved: flag.reserved,
                key_phase: flag.key_phase,
                num_len: num_len as u8,
            },
            ver: 1,
            len,
            num,
            padding: 0,
            dc_id: Buf::Ref(dc_id),
            ..Default::default()
        }
    }

    pub fn is_empty(&self) -> bool {
        self.hdr_len == 0
    }

    pub fn len(&self) -> usize {
        self.hdr_len + self.len - self.flag.num_len as usize
    }

    pub fn hdr_raw(&self) -> &[u8] {
        &self.hdr_raw[..self.hdr_len]
    }

    pub fn hdr_len(&self) -> usize {
        self.hdr_len
    }

    pub fn flag(&self) -> &QUICFlag {
        &self.flag
    }

    pub fn padding_size(&self) -> usize {
        self.padding
    }

    pub fn pd_len(&self) -> usize {
        self.len
    }

    pub fn encode(&mut self) -> Result<(), BufferError> {
        let mut writer = Buffer::from_ptr(&mut self.hdr_raw);
        if self.flag.long_header {
            writer.write_u8(self.flag.encode())?;
            writer.write_u32(self.ver)?;
            writer.write_u8(self.dc_id.len() as u8)?;
            writer.write_slice(self.dc_id.as_ref())?;
            writer.write_u8(self.sc_id.len() as u8)?;
            writer.write_slice(self.sc_id.as_ref())?;
            if self.flag.packet_type == PacketType::Initial {
                crate::quic::write_variant(self.token.len(), &mut writer)?;
                writer.write_slice(self.token.as_ref())?;
            }
            crate::quic::write_variant(self.len, &mut writer)?;
        } else {
            writer.write_u8(self.flag.encode())?;
            writer.write_slice(self.dc_id.as_ref())?;
        }
        self.pn_offset = writer.len();
        match self.flag.num_len() {
            1 => writer.write_u8(self.num as u8)?,
            2 => writer.write_u16(self.num as u16)?,
            4 => writer.write_u32(self.num as u32)?,
            8 => writer.write_slice(&self.num.to_be_bytes())?,
            _ => unreachable!()
        }
        self.hdr_len = writer.len();
        Ok(())
    }


    pub fn from_reader(reader: &mut Reader<'a>) -> Result<QUICPacket<'a>, BufferError> {
        let pos = reader.position();
        let flag = QUICFlag::from_raw(reader.read_u8()?);
        if flag.long_header {
            let ver = reader.read_u32()?;
            let dcid_len = reader.read_u8()? as usize;
            let dc_id = reader.read_slice(dcid_len)?;
            let scid_len = reader.read_u8()? as usize;
            let sc_id = reader.read_slice(scid_len)?;
            let mut token = Buf::Ref(&[]);
            if flag.packet_type == PacketType::Initial {
                let tk_len = crate::quic::read_variant(reader)?;
                token = Buf::Ref(reader.read_slice(tk_len)?);
            };
            Ok(QUICPacket {
                flag,
                ver,
                dc_id: Buf::Ref(dc_id),
                sc_id: Buf::Ref(sc_id),
                token,
                len: crate::quic::read_variant(reader)?,
                pn_offset: reader.position() - pos,
                hdr_raw: reader.inner()[pos..pos + 30].try_into()?,
                ..Default::default()
            })
        } else {
            let mut hdr_raw = [0; 30];
            hdr_raw[0..5].copy_from_slice(&reader.inner()[pos..pos + 5]);
            Ok(QUICPacket {
                flag,
                len: reader.unread_len(),
                pn_offset: reader.position() - pos,
                hdr_raw,
                ..Default::default()
            })
        }
    }

    pub fn decode(&mut self, mask: &[u8], reader: &mut Reader<'a>) -> Result<(), BufferError> {
        if self.flag.long_header {
            self.hdr_raw[0] ^= mask[0] & 0x0f;
        } else {
            self.hdr_raw[0] ^= mask[0] & 0x1f;
        }
        self.flag.decode(self.hdr_raw[0]);
        let pn_offset = self.pn_offset..self.pn_offset + self.flag.num_len();
        if pn_offset.end > self.hdr_raw.len() { return Err(BufferError::Insufficient); }
        self.hdr_raw[pn_offset].iter_mut().enumerate().for_each(|(i, x)| *x ^= mask[i + 1]);
        self.hdr_len = self.pn_offset + self.flag.num_len();
        let mut decode_reader = Reader::from_slice(&self.hdr_raw);
        decode_reader.set_position(self.pn_offset);
        self.num = match self.flag.num_len() {
            1 => decode_reader.read_u8()? as u64,
            2 => decode_reader.read_u16()? as u64,
            3 => decode_reader.read_u24()? as u64,
            4 => decode_reader.read_u32()? as u64,
            _ => unreachable!()
        };
        reader.add_len(self.flag.num_len());
        self.payload = Buf::Ref(reader.read_slice(self.len - self.flag.num_len())?);
        Ok(())
    }

    pub fn dc_id(&self) -> &Buf<'a> {
        &self.dc_id
    }

    pub fn sc_id(&self) -> &Buf<'a> {
        &self.sc_id
    }

    pub fn num(&self) -> u64 {
        self.num
    }
}


#[cfg(test)]
mod tests {
    #[test]
    fn test_en_payload() {}
}