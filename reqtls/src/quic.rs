use std::error::Error;
use std::fmt::{Display, Formatter};
pub use super::message::{AckRange, QUICFrame, QUICFrameFlag, QUICPacket};
pub use crate::connection::{QUICBuffer, QUICConnection};
use crate::{BufferError, ReadExt, Reader, WriteExt};
use std::ops::Range;
use std::str::Utf8Error;
use crate::boring::HashError;

pub fn read_variant(reader: &mut Reader) -> Result<usize, BufferError> {
    if reader.unread_len() == 0 { return Err(BufferError::Insufficient); }
    let flag = reader.current();
    match flag >> 6 {
        0b00 => Ok(reader.read_u8()? as usize),
        0b01 => Ok((reader.read_u16()? & 0x3FFF) as usize),
        0b10 => Ok((reader.read_u32()? & 0x3FFF_FFFF) as usize),
        0b11 => Ok((reader.read_u64()? & 0x3FFF_FFFF_FFFF_FFFF) as usize),
        _ => Err(BufferError::InvalidQUICVariant)
    }
}

pub fn variant_len(val: usize) -> usize {
    match val {
        ..0x40 => 1,
        0x40..0x4000 => 2,
        0x4000..0x4000_0000 => 4,
        0x4000_0000..0x4000_0000_0000_0000 => 8,
        _ => unreachable!()
    }
}


pub fn write_variant<W: WriteExt>(val: usize, writer: &mut W) -> Result<(), BufferError> {
    match val {
        ..0x40 => writer.write_u8(val as u8),
        0x40..0x4000 => writer.write_u16(val as u16 | 0x4000),
        0x4000..0x4000_0000 => writer.write_u32(val as u32 | 0x8000_0000),
        0x4000_0000..0x4000_0000_0000_0000 => writer.write_u64(val as u64 | 0xc000_0000_0000_0000),
        _ => Err(BufferError::InvalidQUICVariant)
    }
}


#[derive(Debug)]
pub struct QUICRange(Vec<Range<u64>>);

impl Default for QUICRange {
    fn default() -> Self {
        QUICRange(Vec::with_capacity(1024))
    }
}

impl QUICRange {
    pub fn insert(&mut self, num: u64) {
        let pos = self.0.iter_mut().position(|r| r.start == num + 1 || r.end + 1 == num);
        if let Some(pos) = pos {
            let range = &mut self.0[pos];
            if range.start == num + 1 {
                range.start = num;
                let opos = self.0.iter_mut().position(|r| r.end + 1 == num);
                if let Some(opos) = opos {
                    self.0[opos].end = self.0[pos].end;
                    self.0.remove(pos);
                }
            } else {
                range.end = num;
                let opos = self.0.iter().position(|r| num + 1 == r.start);
                if let Some(opos) = opos {
                    self.0[pos].end = self.0[opos].end;
                    self.0.remove(opos);
                }
            }
        } else { self.0.push(num..num) }
    }

    pub fn sort(&mut self) {
        self.0.sort_by_key(|a| a.start);
    }

    pub fn get(&self, index: usize) -> &Range<u64> {
        &self.0[index]
    }


    pub fn max_range(&self) -> Option<&Range<u64>> {
        let max = self.0.iter().map(|r| r.end).max()?;
        self.0.iter().find(|r| r.end == max)
    }
    
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn count(&self) -> usize {
        self.0.len()
    }

    pub fn clear(&mut self) {
        let max = if let Some(max) = self.max_range() {
            max.end..max.end
        } else { 0..0 };
        self.0.clear();
        self.0.push(max)
    }
}

#[derive(Debug)]
pub enum QUICError {
    InvalidVariant,
    Buffer(BufferError),
    Hash(HashError),
    Utf8(Utf8Error),
}

impl Error for QUICError {}

impl Display for QUICError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<BufferError> for QUICError {
    fn from(e: BufferError) -> Self {
        QUICError::Buffer(e)
    }
}

impl From<HashError> for QUICError {
    fn from(e: HashError) -> Self {
        QUICError::Hash(e)
    }
}

impl From<Utf8Error> for QUICError {
    fn from(e: Utf8Error) -> Self {
        QUICError::Utf8(e)
    }
}



#[cfg(test)]
mod test {
    use crate::quic::QUICRange;

    #[test]
    fn test_quic_range() {
        let mut range = QUICRange(vec![]);
        for i in [14, 17, 18, 0, 1, 2, 3, 4, 5, 6, 7] {
            range.insert(i);
        }
        range.sort();
        assert_eq!(range.0, vec![0..7, 14..14, 17..18]);
        range.insert(15);
        range.insert(16);
        assert_eq!(range.0, vec![0..7, 14..18]);
        range.insert(13);
        range.insert(12);
        range.insert(11);
        range.insert(10);
        range.insert(9);
        range.insert(8);
        assert_eq!(range.0, vec![0..18]);
    }
}



