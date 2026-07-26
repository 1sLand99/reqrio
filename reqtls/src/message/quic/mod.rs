mod frame;

use std::mem;
use crate::{Buf, Buffer, BufferError, ReadExt, Reader, WriteExt};
pub use frame::QUICFrame;


#[derive(Default, Copy, Clone, Debug, PartialEq)]
pub enum PacketType {
    #[default]
    Initial = 0,
    Handshake = 2,
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


#[derive(Default, Debug)]
pub struct QUICFlag {
    long_header: bool,
    fixed_bit: bool,
    packet_type: PacketType,
    reserved: u8,
    num_len: u8,
}

impl QUICFlag {
    pub fn from_raw(v: u8) -> QUICFlag {
        QUICFlag {
            long_header: v & 0x80 == 0x80,
            fixed_bit: v & 0x40 == 0x40,
            packet_type: ((v & 0x30) >> 4).into(),
            reserved: 0,
            num_len: 0,
        }
    }

    fn decode(&mut self, v: u8) {
        self.reserved = v & 0xc >> 2;
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
    len: usize,
    pub(crate) pn_offset: usize,
    pub(crate) num: u64,
    pub(crate) payload: Buf<'a>,

    pub(crate) hdr_raw: [u8; 30],
    pub(crate) hdr_len: usize,
    pub(crate) padding: usize,
    pub(crate) frames: Vec<QUICFrame<'a>>,
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
            frames: vec![],
        }
    }
}

impl<'a> QUICPacket<'a> {
    pub fn new_initial(num: u64, pd_len: usize, dcid: &'a [u8]) -> Self {
        let num_len = crate::quic::variant_len(num as usize);
        let (len, padding) = if pd_len + num_len + 16 >= 1232 {
            (pd_len + num_len + 16, 0)
        } else { (1232, 1232 - pd_len - num_len - 16) };
        QUICPacket {
            flag: QUICFlag {
                long_header: true,
                fixed_bit: true,
                packet_type: PacketType::Initial,
                reserved: 0,
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

    pub fn new_ack(packet: &QUICPacket, pd_len: usize) -> Self {
        let num_len = crate::quic::variant_len(packet.num as usize);
        let len = pd_len + num_len + 16;
        QUICPacket {
            flag: QUICFlag {
                long_header: packet.flag.long_header,
                fixed_bit: true,
                packet_type: packet.flag.packet_type,
                reserved: 0,
                num_len: num_len as u8,
            },
            ver: 1,
            len,
            num: packet.num,
            padding: 0,
            dc_id: Buf::Vec(packet.sc_id.to_vec()),
            ..Default::default()
        }
    }

    pub fn is_empty(&self) -> bool {
        self.hdr_len == 0
    }

    pub fn len(&self) -> usize {
        self.hdr_len + self.len
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
            crate::quic::write_variant(self.token.len(), &mut writer)?;
            writer.write_slice(self.token.as_ref())?;
            crate::quic::write_variant(self.len, &mut writer)?;
            self.pn_offset = writer.len();
            match self.flag.num_len() {
                1 => writer.write_u8(self.num as u8)?,
                2 => writer.write_u16(self.num as u16)?,
                4 => writer.write_u32(self.num as u32)?,
                8 => writer.write_slice(&self.num.to_be_bytes())?,
                _ => unreachable!()
            }
            self.hdr_len = writer.len();
        } else {
            todo!()
        }
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
        } else { Ok(QUICPacket::default()) }
    }

    pub fn decode(&mut self, mask: &[u8], reader: &mut Reader<'a>) -> Result<(), BufferError> {
        if self.flag.long_header {
            self.hdr_raw[0] ^= mask[0] & 0x0f;
            self.flag.decode(self.hdr_raw[0]);
            let pn_offset = self.pn_offset..self.pn_offset + self.flag.num_len();
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
        } else {
            self.hdr_raw[0] ^= mask[0] & 0x1f;
            todo!()
            // let mut decode_reader = Reader::from_slice(&self.hdr_raw);
            // self.num = match self.flag.num_len() {
            //     1 => decode_reader.read_u8()? as u64,
            //     2 => decode_reader.read_u16()? as u64,
            //     3 => decode_reader.read_u24()? as u64,
            //     4 => decode_reader.read_u32()? as u64,
            //     _ => unreachable!()
            // };
            // reader.add_len(self.flag.num_len());
            // self.payload = Buf::Ref(reader.read_slice(self.len - self.flag.num_len())?);
        }

        Ok(())
    }

    pub fn dc_id(&self) -> &Buf<'a> {
        &self.dc_id
    }

    pub fn num(&self) -> u64 {
        self.num
    }

    pub fn push_frame(&mut self, frame: QUICFrame<'a>) {
        self.frames.push(frame);
    }

    pub fn take_frames(&mut self) -> Vec<QUICFrame<'a>> {
        mem::take(&mut self.frames)
    }
}


#[cfg(test)]
mod tests {
    #[test]
    fn test_en_payload() {}
}