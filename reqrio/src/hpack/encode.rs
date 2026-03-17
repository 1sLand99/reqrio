use crate::hpack::table::Table;
use reqtls::WriteExt;
use crate::error::HlsResult;
use crate::hpack::{huffman, HPackItem};
use crate::hpack::index::Index;

pub struct HpackEncode {
    table: Table,
}

impl Default for HpackEncode {
    fn default() -> Self {
        HpackEncode::new(4096)
    }
}

impl HpackEncode {
    pub fn new(max_table_size: usize) -> Self {
        HpackEncode {
            table: Table::new(max_table_size),
        }
    }

    fn encode_integer<W: WriteExt>(&self, mut value: usize, writer: &mut W) {
        while value >= 128 {
            writer.write_u8(0b1000_0000 | value as u8);
            value >>= 7;
        }
        writer.write_u8(value as u8);
    }

    fn encode_index<W: WriteExt>(&self, index: Index, writer: &mut W) {
        let finish = index.write_to(writer);
        if finish { return; }
        self.encode_integer(index.remain(), writer);
    }

    fn encode_string<W: WriteExt>(&self, value: impl AsRef<[u8]>, huffman: bool, writer: &mut W) -> HlsResult<()> {
        match huffman {
            true => {
                let value = huffman::encode(value.as_ref())?;
                let index = Index::ValueLen { huffman, value: value.len() };
                let finish = index.write_to(writer);
                if !finish { self.encode_integer(index.remain(), writer); }
                writer.write_slice(&value);
            }
            false => {
                let index = Index::ValueLen { huffman, value: value.as_ref().len() };
                let finish = index.write_to(writer);
                if !finish { self.encode_integer(index.remain(), writer); }
                writer.write_slice(value.as_ref());
            }
        }
        Ok(())
    }

    pub fn encode_one<W: WriteExt>(&mut self, name: impl AsRef<str>, value: impl AsRef<str>, writer: &mut W) -> HlsResult<()> {
        let name = name.as_ref();
        let value = value.as_ref();
        let item = self.table.get_by_name_value(name, value);
        match item {
            None => match self.table.get_by_name(name) {
                None => {
                    let index = Index::NoIndexAdd;
                    index.write_to(writer);
                    self.encode_string(name, true, writer)?;
                    self.encode_string(value, true, writer)?;
                    let item = HPackItem::new(name, value);
                    self.table.insert(item);
                }
                Some(index) => {
                    let finish = index.write_to(writer);
                    if !finish { self.encode_integer(index.remain(), writer); }
                    self.encode_string(value, true, writer)?;
                    let item = HPackItem::new(name, value);
                    self.table.insert(item);
                }
            }
            Some(index) => {
                let finish = index.write_to(writer);
                if !finish { self.encode_integer(index.remain(), writer); }
            }
        }
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use crate::Buffer;
    use crate::hpack::encode::HpackEncode;
    use crate::hpack::index::Index;

    #[test]
    fn test_index_encode() {
        let encoder = HpackEncode::default();
        //test-indexed
        let mut buffer = Buffer::with_capacity(1024);
        encoder.encode_index(Index::Indexed(33), &mut buffer);
        encoder.encode_index(Index::Indexed(234), &mut buffer);
        encoder.encode_index(Index::Indexed(898), &mut buffer);
        encoder.encode_index(Index::Indexed(67238734), &mut buffer);
        assert_eq!(buffer.filled(), [161, 255, 107, 255, 131, 6, 255, 207, 245, 135, 32]);
        buffer.reset();
        //test-name-indexed
        encoder.encode_index(Index::NameIndexedAdd(33), &mut buffer);
        encoder.encode_index(Index::NameIndexedAdd(234), &mut buffer);
        encoder.encode_index(Index::NameIndexedAdd(898), &mut buffer);
        encoder.encode_index(Index::NameIndexedAdd(67238734), &mut buffer);
        assert_eq!(buffer.filled(), [97, 127, 171, 1, 127, 195, 6, 127, 143, 246, 135, 32]);
        buffer.reset();
        //test-name-indexed-never
        encoder.encode_index(Index::NameIndexedOnce(33), &mut buffer);
        encoder.encode_index(Index::NameIndexedOnce(234), &mut buffer);
        encoder.encode_index(Index::NameIndexedOnce(898), &mut buffer);
        encoder.encode_index(Index::NameIndexedOnce(67238734), &mut buffer);
        assert_eq!(buffer.filled(), [15, 18, 15, 219, 1, 15, 243, 6, 15, 191, 246, 135, 32])
    }

    #[test]
    fn test_string_encode() {
        let encoder = HpackEncode::default();
        let mut buffer = Buffer::with_capacity(1024);
        encoder.encode_string("foo".as_bytes(), false, &mut buffer).unwrap();
        assert_eq!(buffer.filled(), [3, 102, 111, 111]);
        buffer.reset();
        encoder.encode_string("foo".as_bytes(), true, &mut buffer).unwrap();
        assert_eq!(buffer.filled(), [130, 148, 231]);
        println!("{:?}", buffer.filled());
    }

    #[test]
    fn test_hpack_encode() {
        let mut buffer = Buffer::with_capacity(1024);
        let mut encode = HpackEncode::default();
        //static table indexed
        encode.encode_one(":method", "GET", &mut buffer).unwrap();
        assert_eq!(buffer.filled(), [130]);
        buffer.reset();
        //name indexed
        encode.encode_one(":method", "DELETE", &mut buffer).unwrap();
        assert_eq!(buffer.filled(), [66, 134, 191, 131, 62, 13, 248, 63]);
        buffer.reset();
        //dynamic indexed
        encode.encode_one(":method", "DELETE", &mut buffer).unwrap();
        assert_eq!(buffer.filled(), [190]);
        buffer.reset();
        encode.encode_one("new name", "new string", &mut buffer).unwrap();
        assert_eq!(buffer.filled(), [64, 134, 168, 190, 20, 168, 116, 151, 136, 168, 190, 20, 66, 108, 53, 83, 127]);
        println!("{:?}", buffer.filled());
    }
}