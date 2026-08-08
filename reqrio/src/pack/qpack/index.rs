use crate::pack::qpack::index::Index::{Increment, NamePostBase};
use crate::pack::qpack::QPackType;
use crate::HlsError;
use reqtls::{ReadExt, Reader};

#[derive(Debug)]
#[cfg_attr(debug_assertions, derive(PartialEq))]
pub enum Index {
    //--------------------------->encoder<---------------------------
    ///更新动态表大小
    /// ```text
    ///  0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 0 | 1 |   Capacity (5+)   |
    /// +---+---+---+-------------------+
    /// ```
    DynamicTableCapacity(usize),
    ///name在编/解码表内存在，但value不存在，应追加到动态表中
    /// ```text
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 1 | T |    Name Index (6+)    |
    /// +---+---+-----------------------+
    /// | H |     Value Length (7+)     |
    /// +---+---------------------------+
    /// |  Value String (Length bytes)  |
    /// +-------------------------------+
    /// ```
    IndexedName {
        idx_dyn: bool,
        index: usize,
    },
    /// name和value在编/解码表内不存在，应追加到动态表中
    /// ```text
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 1 | H | Name Length (5+)  |
    /// +---+---+---+-------------------+
    /// |  Name String (Length bytes)   |
    /// +---+---------------------------+
    /// | H |     Value Length (7+)     |
    /// +---+---------------------------+
    /// |  Value String (Length bytes)  |
    /// +-------------------------------+
    /// ```
    NewName {
        huffman: bool,
        name_len: usize,
    },
    /// 复制动态表中已存在的条目
    /// ```text
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 0 | 0 |    Index (5+)     |
    /// +---+---+---+-------------------+
    ///```
    Duplicate(usize),
    //----------------------------->decoder<----------------------------
    ///Section Acknowledgment
    /// ```text
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 1 |      Stream ID (7+)       |
    /// +---+---------------------------+
    ///```
    Acknowledgment(u64),
    /// stream reset or reading is abandoned
    /// ```text
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 1 |     Stream ID (6+)    |
    /// +---+---+-----------------------+
    ///```
    StreamCancellation(u64),
    /// 已经收到并处理到第x个动态表插入
    ///```text
    ///  0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 0 |     Increment (6+)    |
    /// +---+---+-----------------------+
    ///```
    Increment(usize),
    //---------------------------->stream<----------------------------
    ///所需插入计数
    /// ```text
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// |   Required Insert Count (8+)  |
    /// +---+---------------------------+
    /// | S |      Delta Base (7+)      |
    /// +---+---------------------------+
    /// |      Encoded Field Lines    ...
    /// +-------------------------------+
    ///  if Sign == 0:
    ///       Base = ReqInsertCount + DeltaBase
    ///    else:
    ///       Base = ReqInsertCount - DeltaBase - 1
    /// ```
    EncodedHead {
        enc_count: usize,
        base: usize,
        sign: bool,
    },
    ///name-value均能在表内找到
    /// ```text
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 1 | T |      Index (6+)       |
    /// +---+---+-----------------------+
    /// ```
    Indexed {
        idx_dyn: bool,
        index: usize,
    },
    ///Indexed Field Line with Post-Base Index
    ///```text
    ///  0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 0 | 0 | 1 |  Index (4+)   |
    /// +---+---+---+---+---------------+
    /// ```
    PostBase(usize),
    ///name在编/解码表内存在，但value不存在，应追加到动态表中，N表示是否插入到动态表
    /// ```text
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 1 | N | T |Name Index (4+)|
    /// +---+---+---+---+---------------+
    /// | H |     Value Length (7+)     |
    /// +---+---------------------------+
    /// |  Value String (Length bytes)  |
    /// +-------------------------------+
    ///```
    NamedIndexed {
        req_insert: bool,
        idx_dyn: bool,
        index: usize,

    },
    ///Literal Field Line with Post-Base Name Reference
    /// ```text
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 0 | 0 | 0 | N |NameIdx(3+)|
    /// +---+---+---+---+---+-----------+
    /// | H |     Value Length (7+)     |
    /// +---+---------------------------+
    /// |  Value String (Length bytes)  |
    /// +-------------------------------+
    /// ```
    NamePostBase {
        req_insert: bool,
        index: usize,
    },
    ///Literal Field Line with Literal Name
    /// ```text
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 0 | 1 | N | H |NameLen(3+)|
    /// +---+---+---+---+---+-----------+
    /// |  Name String (Length bytes)   |
    /// +---+---------------------------+
    /// | H |     Value Length (7+)     |
    /// +---+---------------------------+
    /// |  Value String (Length bytes)  |
    /// +-------------------------------+
    /// ```
    LiteralNameValue {
        req_insert: bool,
        name_len: usize,
        huffman: bool,
    },

}

impl Index {
    ///stream decode
    pub fn from_reader(typ: QPackType, read: bool, reader: &mut Reader) -> Result<Index, HlsError> {
        match typ {
            QPackType::Stream => {
                let typ = reader.read_u8()?;
                if !read {
                    let mut insert = typ as usize & 0xFF;
                    if typ == 0xff {
                        insert += super::super::decode_integer(reader)?
                    }
                    let base = reader.read_u8()? as usize;
                    let sign = base & 0x80 == 0x80;
                    let mut base = base & 0x7F;
                    if base & 0x7F == 0x7F {
                        base += super::super::decode_integer(reader)?;
                    }
                    return Ok(Index::EncodedHead {
                        enc_count: insert,
                        base,
                        sign,
                    });
                }
                if typ & 0x80 == 0x80 {
                    let mut value = typ as usize & 0x3F;
                    if value == 0x3F {
                        value += super::super::decode_integer(reader)?;
                    }
                    Ok(Index::Indexed {
                        idx_dyn: typ & 0x40 != 0x40,
                        index: value,
                    })
                } else if typ & 0x40 == 0x40 {
                    let mut value = typ as usize & 0xF;
                    if value == 0xF {
                        value += super::super::decode_integer(reader)?;
                    };
                    Ok(Index::NamedIndexed {
                        req_insert: typ & 0x20 == 0x20,
                        idx_dyn: typ & 0x10 != 0x10,
                        index: value,
                    })
                } else if typ & 0x10 == 0x10 {
                    let mut value = typ as usize & 0xF;
                    if value == 0xF {
                        value += super::super::decode_integer(reader)?;
                    }
                    Ok(Index::PostBase(value))
                } else if typ & 0x20 == 0x20 {
                    let mut value = typ as usize & 0x7;
                    if value == 0x7 {
                        value += super::super::decode_integer(reader)?;
                    }
                    Ok(Index::LiteralNameValue {
                        req_insert: typ & 0x10 == 0x10,
                        name_len: value,
                        huffman: typ & 0x8 == 0x8,
                    })
                } else if typ >> 4 == 0 {
                    let mut value = typ as usize & 0x7;
                    if value == 0x7 {
                        value += super::super::decode_integer(reader)?;
                    }
                    Ok(NamePostBase {
                        req_insert: typ & 0x8 == 0x8,
                        index: value,
                    })
                } else { unreachable!() }
            }
            QPackType::StreamEncoder => {
                let typ = reader.read_u8()?;
                if typ >> 5 == 1 {
                    let mut value = typ as usize & 0x1F;
                    if value == 0x1F {
                        value += super::super::decode_integer(reader)?;
                    }
                    Ok(Index::DynamicTableCapacity(value))
                } else if typ & 0x80 == 0x80 {
                    let mut value = typ as usize & 0x3F;
                    if value == 0x3F {
                        value += super::super::decode_integer(reader)?;
                    }
                    Ok(Index::IndexedName {
                        idx_dyn: typ & 0x40 != 0x40,
                        index: value,
                    })
                } else if typ >> 6 == 1 {
                    let mut value = typ as usize & 0x1F;
                    if value == 0x1F {
                        value += super::super::decode_integer(reader)?;
                    }
                    Ok(Index::NewName {
                        huffman: typ & 0x20 == 0x20,
                        name_len: value,
                    })
                } else if typ >> 5 == 0 {
                    let mut value = typ as usize & 0x1F;
                    if value == 0x1F {
                        value += super::super::decode_integer(reader)?;
                    }
                    Ok(Index::Duplicate(value))
                } else { unreachable!() }
            }
            QPackType::StreamDecoder => {
                let typ = reader.read_u8()?;
                if typ & 0x80 == 0x80 {
                    let mut value = typ as usize & 0x7F;
                    if value == 0x7F {
                        value += super::super::decode_integer(reader)?;
                    }
                    Ok(Index::Acknowledgment(value as u64))
                } else if typ & 0x40 == 0x40 {
                    let mut value = typ as u64 & 0x3F;
                    if value == 0x3F {
                        value += super::super::decode_integer(reader)? as u64;
                    }
                    Ok(Index::StreamCancellation(value))
                } else if typ >> 6 == 0 {
                    let mut value = typ as usize & 0x3F;
                    if value == 0x3F {
                        value += super::super::decode_integer(reader)?;
                    }
                    Ok(Increment(value))
                } else { unreachable!() }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::pack::qpack::index::Index;
    use crate::pack::qpack::QPackType;
    use crate::hex;
    use reqtls::Reader;

    #[test]
    fn test_qpack_index1() {
        let data = hex::decode("000051").unwrap();
        let mut read = false;
        let mut reader = Reader::from_slice(&data);
        let index = Index::from_reader(QPackType::Stream, read, &mut reader).unwrap();
        assert_eq!(index, Index::EncodedHead { enc_count: 0, base: 0, sign: false });
        read = true;
        let index = Index::from_reader(QPackType::Stream, read, &mut reader).unwrap();
        assert_eq!(index, Index::NamedIndexed {
            req_insert: false,
            idx_dyn: false,
            index: 1
        });
    }

    #[test]
    fn test_qpack_index2() {
        let data = hex::decode("3fbd01c0c14a02").unwrap();
        let mut read = false;
        let mut reader = Reader::from_slice(&data);
        let index = Index::from_reader(QPackType::StreamEncoder, read, &mut reader).unwrap();
        assert_eq!(index, Index::DynamicTableCapacity(220));
        read = true;
        let index = Index::from_reader(QPackType::StreamEncoder, read, &mut reader).unwrap();
        assert_eq!(index, Index::IndexedName { idx_dyn: false, index: 0 });
        let index = Index::from_reader(QPackType::StreamEncoder, read, &mut reader).unwrap();
        assert_eq!(index, Index::IndexedName { idx_dyn: false, index: 1 });
        let index = Index::from_reader(QPackType::StreamEncoder, read, &mut reader).unwrap();
        let Index::NewName { huffman, name_len } = index else { panic!("index decode error") };
        assert!(!huffman);
        assert_eq!(name_len, 10);
        let index = Index::from_reader(QPackType::StreamEncoder, read, &mut reader).unwrap();
        assert_eq!(index, Index::Duplicate(2))
    }

    #[test]
    fn test_qpack_index3() {
        let data = hex::decode("480184").unwrap();
        let mut reader = Reader::from_slice(&data);
        let index = Index::from_reader(QPackType::StreamDecoder, false, &mut reader).unwrap();
        assert_eq!(index, Index::StreamCancellation(8));
        let index = Index::from_reader(QPackType::StreamDecoder, false, &mut reader).unwrap();
        assert_eq!(index, Index::Increment(1));
        let index = Index::from_reader(QPackType::StreamDecoder, false, &mut reader).unwrap();
        assert_eq!(index, Index::Acknowledgment(4))
    }
}