pub mod table;

use super::error::HuffmanError;

pub fn encode(src: &[u8]) -> Result<Vec<u8>, HuffmanError> {
    let mut bits: u64 = 0;
    let mut bits_left = 40;
    let codings = table::ENCODE_TABLE; // parsed huffman table
    let mut dst = vec![];
    for &byte in src {
        let (code_len, code) = codings.get(byte as usize).ok_or(HuffmanError::ByteEncodeInvalid)?;
        bits |= (*code as u64) << (bits_left - code_len); // shift and add old and new numbers
        bits_left -= code_len;

        while bits_left <= 32 {
            dst.push((bits >> 32) as u8);

            bits <<= 8; // add more room for the next character
            bits_left += 8;
        }
    }

    if bits_left != 40 { // finalize with EOS
        bits |= (1 << bits_left) - 1; // add EOS and pedding
        dst.push((bits >> 32) as u8);
    }

    Ok(dst)
}