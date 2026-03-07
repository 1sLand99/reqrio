mod input;
mod primitives;

pub use input::*;
use super::error::HPackError;
use super::table::Table;


#[derive(Debug, Default)]
pub struct Encoder<'a> {
    /// A store for the static and the dynamic headers.
    table: Table<'a>,
}

#[allow(unused)]
impl<'a> Encoder<'a> {
    /// A flag indicating to encode header name with Huffman algorithm (`0x1`).
    pub const HUFFMAN_NAME: u8 = 0x1;

    /// A flag indicating to encode header value with Huffman algorithm (`0x2`).
    pub const HUFFMAN_VALUE: u8 = 0x2;

    /// A flag indicating to index literal header field (`0x4`).
    pub const WITH_INDEXING: u8 = 0x4;

    /// A flag indicating to never index literal header field (`0x8`).
    pub const NEVER_INDEXED: u8 = 0x8;

    /// A flag indicating to find the best literal representation by searching
    /// the indexing table (`0x10`).
    pub const BEST_FORMAT: u8 = 0x10;

    /// Returns a new encoder instance with the provided maximum allowed size of
    /// the dynamic table.
    pub fn with_dynamic_size(max_dynamic_size: u32) -> Self {
        Self {
            table: Table::with_dynamic_size(max_dynamic_size),
        }
    }

    /// Returns the maximum allowed size of the dynamic table.
    pub fn max_dynamic_size(&mut self) -> u32 {
        self.table.max_dynamic_size()
    }


    /// byte `flags`:
    ///
    /// * `0x1`: Use Huffman to encode header name.
    /// * `0x2`: Use Huffman to encode header value.
    /// * `0x4`: Literal header field with incremental indexing ([6.2.1.]).
    /// * `0x8`: Literal header field never indexed ([6.2.3.]).
    /// * `0x10`: Encode literal as the best representation.
    pub fn encode<F>(
        &mut self,
        field: F,
    ) -> Result<Vec<u8>, HPackError>
    where
        F: Into<EncoderInput>,
    {
        match field.into() {
            EncoderInput::Indexed(index) => self.encode_indexed(index),
            EncoderInput::IndexedName(index, value, flags) => self.encode_indexed_name(index, value, flags),
            EncoderInput::Literal(name, value, flags) => {
                if flags & 0x10 == 0x10 {
                    match self.table.find(&name, &value) {
                        Some((index, true)) => self.encode_indexed(index as u32),
                        Some((index, false)) => self.encode_indexed_name(index as u32, value, flags),
                        None => self.encode_literal(name, value, flags),
                    }
                } else {
                    self.encode_literal(name, value, flags)
                }
            }
        }
    }

    /// Encodes a header that exists at `index` in the indexing table.
    ///
    /// The function converts the header index into HPACK's indexed header field
    /// representation and writes it into the `dst` buffer.
    ///
    /// **Indexed header field representation ([6.1.], figure 5):**
    ///
    /// ```txt
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 1 |        Index (7+)         |
    /// +---+---------------------------+
    /// ```
    ///
    /// [6.1.]: https://tools.ietf.org/html/rfc7541#section-6.1
    pub fn encode_indexed(
        &self,
        index: u32,
    ) -> Result<Vec<u8>, HPackError> {
        self.table.get(index).ok_or(HPackError::InvalidIndex)?;
        primitives::encode_integer(index, 0x80, 7)
    }

    /// Encodes a header where its name is represented with an `index` from the
    /// indexing table and the `value` is provided in bytes.
    ///
    /// This function converts the header into HPACK's literal header field
    /// representation and writes it into the `dst` buffer.
    ///
    /// **Literal header field with incremental indexing ([6.2.1.], figure 6):**
    ///
    /// ```txt
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 1 |      Index (6+)       |
    /// +---+---+-----------------------+
    /// | H |     Value Length (7+)     |
    /// +---+---------------------------+
    /// | Value String (Length octets)  |
    /// +-------------------------------+
    /// ```
    ///
    /// **Literal header field without indexing ([6.2.2.], figure 8):**
    ///
    /// ```txt
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 0 | 0 | 0 |  Index (4+)   |
    /// +---+---+-----------------------+
    /// | H |     Value Length (7+)     |
    /// +---+---------------------------+
    /// | Value String (Length octets)  |
    /// +-------------------------------+
    /// ```
    ///
    /// **Literal header field never indexed ([6.2.3.], figure 10):**
    ///
    /// ```txt
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 0 | 0 | 1 |  Index (4+)   |
    /// +---+---+-----------------------+
    /// | H |     Value Length (7+)     |
    /// +---+---------------------------+
    /// | Value String (Length octets)  |
    /// +-------------------------------+
    /// ```
    ///
    /// By default headers are represented as literals without indexing and
    /// header's value is encoded as a string. We can configure the encoder by
    /// providing byte `flags`:
    ///
    /// * `0x2`: Use Huffman to encode header value.
    /// * `0x4`: Literal header field with incremental indexing ([6.2.1.]).
    /// * `0x8`: Literal header field never indexed ([6.2.3.]).
    ///
    /// [6.2.1.]: https://tools.ietf.org/html/rfc7541#section-6.2.1
    /// [6.2.2.]: https://tools.ietf.org/html/rfc7541#section-6.2.2
    /// [6.2.3.]: https://tools.ietf.org/html/rfc7541#section-6.2.3
    pub fn encode_indexed_name(
        &mut self,
        index: u32,
        value: Vec<u8>,
        flags: u8,
    ) -> Result<Vec<u8>, HPackError> {
        let mut dst = vec![];
        let name = self.table.get(index).ok_or(HPackError::InvalidIndex)?.0;
        if flags & 0x4 == 0x4 {
            self.table.insert(name.to_vec(), value.clone());
            dst.extend(primitives::encode_integer(index, 0x40, 6)?);
        } else if flags & 0x8 == 0x8 {
            dst.extend(primitives::encode_integer(index, 0b00010000, 4)?)
        } else { // without indexing
            dst.extend(primitives::encode_integer(index, 0x0, 4)?)
        }

        dst.extend(primitives::encode_string(value, flags & 0x2 == 0x2)?);
        Ok(dst)
    }

    /// Encodes a header where its name and value are provided in bytes.
    ///
    /// This function converts the header into HPACK's literal header field
    /// representation and writes it into the `dst` buffer.
    ///
    /// **Literal header field with incremental indexing ([6.2.1.], figure 7):**
    ///
    /// ```txt
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 1 |           0           |
    /// +---+---+-----------------------+
    /// | H |     Name Length (7+)      |
    /// +---+---------------------------+
    /// |  Name String (Length octets)  |
    /// +---+---------------------------+
    /// | H |     Value Length (7+)     |
    /// +---+---------------------------+
    /// | Value String (Length octets)  |
    /// +-------------------------------+
    /// ```
    ///
    /// **Literal header field without indexing ([6.2.2.], figure 9):**
    ///
    /// ```txt
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 0 | 0 | 0 |       0       |
    /// +---+---+-----------------------+
    /// | H |     Name Length (7+)      |
    /// +---+---------------------------+
    /// |  Name String (Length octets)  |
    /// +---+---------------------------+
    /// | H |     Value Length (7+)     |
    /// +---+---------------------------+
    /// | Value String (Length octets)  |
    /// +-------------------------------+
    /// ```
    ///
    /// **Literal header field never indexed ([6.2.3.], figure 11):**
    ///
    /// ```txt
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 0 | 0 | 1 |       0       |
    /// +---+---+-----------------------+
    /// | H |     Name Length (7+)      |
    /// +---+---------------------------+
    /// |  Name String (Length octets)  |
    /// +---+---------------------------+
    /// | H |     Value Length (7+)     |
    /// +---+---------------------------+
    /// | Value String (Length octets)  |
    /// +-------------------------------+
    /// ```
    ///
    /// By default headers are represented as literals without indexing. Heder's
    /// name and value are encoded as a string. We can configure the encoder by
    /// providing byte `flags`:
    ///
    /// * `0x1`: Use Huffman to encode header name.
    /// * `0x2`: Use Huffman to encode header value.
    /// * `0x4`: Literal header field with incremental indexing ([6.2.1.]).
    /// * `0x8`: Literal header field never indexed ([6.2.3.]).
    pub fn encode_literal(
        &mut self,
        name: Vec<u8>,
        value: Vec<u8>,
        flags: u8,
    ) -> Result<Vec<u8>, HPackError> {
        let mut dst = vec![];
        if flags & 0x4 == 0x4 {
            dst.push(0x40);
            self.table.insert(name.clone(), value.clone());
        } else if flags & 0x8 == 0x8 {
            dst.push(0b00010000);
        } else { // without indexing
            dst.push(0x0);
        }

        dst.extend(primitives::encode_string(name, flags & 0x1 == 0x1)?);
        dst.extend(primitives::encode_string(value, flags & 0x2 == 0x2)?);
        Ok(dst)
    }

    /// **Maximum Dynamic table size change ([6.3.], figure 12):**
    ///
    /// ```txt
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 0 | 1 |   Max size (5+)   |
    /// +---+---------------------------+
    /// ```
    ///
    /// [6.3]: https://tools.ietf.org/html/rfc7541#section-6.3
    pub fn update_max_dynamic_size(
        &mut self,
        size: u32,
    ) -> Result<Vec<u8>, HPackError> {
        self.table.update_max_dynamic_size(size);
        primitives::encode_integer(size, 0b00100000, 5)
    }
}
