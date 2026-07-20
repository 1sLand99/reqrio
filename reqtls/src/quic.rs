use crate::{BufferError, ReadExt, Reader, WriteExt};

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


pub(crate) fn write_variant<W: WriteExt>(val: usize, writer: &mut W) -> Result<(), BufferError> {
    match val {
        ..0x40 => writer.write_u8(val as u8),
        0x40..0x40FF => writer.write_u16(val as u16 | 0xc000),
        0x40FF..0x40FF_FFFF => writer.write_u32(val as u32 | 0xc000_0000),
        0x40FF_FFFF..0x40FF_FFFF_FFFF_FFFF => writer.write_slice(&(val as u64 | 0xc000_0000_0000_0000).to_be_bytes()),
        _ => Err(BufferError::InvalidQUICVariant)
    }
}