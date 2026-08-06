mod hpack;
mod item;
mod error;
pub mod huffman;
mod qpack;

pub use hpack::{HPackCoding, HPackEncode, HPackDecode};
pub use item::HPackItem;
pub use error::HPackError;
use reqtls::{ReadExt, Reader};
use crate::error::HlsResult;

fn decode_integer(buf: &mut Reader) -> HlsResult<usize> {
    let mut res = 0;
    let mut shift = 0;
    loop {
        let byte = buf.read_u8()?;
        res |= ((byte & 0b0111_1111) as usize) << shift;
        shift += 7;
        if byte >> 7 == 0 { break; }
    }
    Ok(res)
}