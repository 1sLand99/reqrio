use crate::{BufferError, ReadExt, Reader, WriteExt};
pub use crate::connection::{QUICBuffer, QUICError, QUICConnection};
pub use super::message::{FrameType, QUICPacket};


pub(crate) fn read_variant(reader: &mut Reader) -> Result<usize, BufferError> {
    let flag = reader.current();
    match flag >> 6 {
        0b00 => Ok(reader.read_u8()? as usize),
        0b01 => Ok((reader.read_u16()? & 0x3FFF) as usize),
        0b10 => Ok((reader.read_u32()? & 0x3FFF_FFFF) as usize),
        0b11 => Ok((reader.read_u64()? & 0x3FFF_FFFF_FFFF_FFFF) as usize),
        _ => Err(BufferError::InvalidQUICVariant)
    }
}

pub(crate) fn variant_len(val: usize) -> usize {
    match val {
        ..0x40 => 1,
        0x40..0x4000 => 2,
        0x4000..0x4000_0000 => 4,
        0x4000_0000..0x4000_0000_0000_0000 => 8,
        _ => unreachable!()
    }
}


pub(crate) fn write_variant<W: WriteExt>(val: usize, writer: &mut W) -> Result<(), BufferError> {
    match val {
        ..0x40 => writer.write_u8(val as u8),
        0x40..0x4000 => writer.write_u16(val as u16 | 0x4000),
        0x4000..0x4000_0000 => writer.write_u32(val as u32 | 0x8000_0000),
        0x4000_0000..0x4000_0000_0000_0000 => writer.write_slice(&(val as u64 | 0xc000_0000_0000_0000).to_be_bytes()),
        _ => Err(BufferError::InvalidQUICVariant)
    }
}