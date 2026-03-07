use crate::huffman;
use super::super::error::HPackError;

/// **Integer value encoded within the 5-bit prefix ([5.1.], figure 2):**
///
/// ```txt
///   0   1   2   3   4   5   6   7
/// +---+---+---+---+---+---+---+---+
/// | ? | ? | ? |       value       |
/// +---+---+---+-------------------+
/// ```
///
/// **Integer value encoded after the 5-bit prefix ([5.1.], figure 3):**
///
/// ```txt
///   0   1   2   3   4   5   6   7
/// +---+---+---+---+---+---+---+---+
/// | ? | ? | ? | 1   1   1   1   1 |
/// +---+---+---+-------------------+
/// | 1 |    Value-(2^N-1) LSB      |
/// +---+---------------------------+
///                ...
/// +---+---------------------------+
/// | 0 |    Value-(2^N-1) MSB      |
/// +---+---------------------------+
/// ```

pub(crate) fn encode_integer(
    value: u32,
    flags: u8,
    prefix_size: u8,
) -> Result<Vec<u8>, HPackError> {
    let mut dst = vec![];
    if prefix_size < 1 || prefix_size > 8 { return Err(HPackError::InvalidPrefix); }

    let mask = ((1 << prefix_size) - 1) as u8; // max possible value of the first byte
    let flags = flags & 255 - mask; // remove invalid flags

    if value < mask as u32 { // small enought to fit intothe first byte
        dst.push(flags | value as u8);
        return Ok(dst);
    }

    let mut value = value - mask as u32;
    dst.push(flags | mask); // first byte
    while value >= 128 {
        dst.push(0b10000000 | value as u8); // byte with continuation flag
        value >>= 7;
    }
    dst.push(value as u8); // last byte
    Ok(dst)
}


/// **String literal representation ([5.2.], figure 4):**
///
/// ```txt
///   0   1   2   3   4   5   6   7
/// +---+---+---+---+---+---+---+---+
/// | H |    String Length (7+)     |
/// +---+---------------------------+
/// |  String Data (Length octets)  |
/// +-------------------------------+
/// ```
///
pub(crate) fn encode_string(
    data: Vec<u8>,
    huffman: bool,
) -> Result<Vec<u8>, HPackError> {
    let (flags, bytes) = match huffman {
        true => (0x80, huffman::encode(&data)?),
        false => (0, data.to_vec())
    };
    let mut dst = encode_integer(bytes.len() as u32, flags, 7)?; // first byte
    dst.extend(bytes);
    Ok(dst)
}
