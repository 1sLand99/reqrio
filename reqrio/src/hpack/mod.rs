pub use error::HPackError;
pub use item::HPackItem;
pub use encode::HPackEncode;
pub use decode::{HPackDecode, HPackDecodeBuf};

mod encode;
mod decode;
mod error;
mod item;
mod table;
mod index;
mod huffman;

pub struct HPackCoding {
    decoder: HPackDecode,
    encoder: HPackEncode,
}

impl HPackCoding {
    pub fn new(size: usize) -> HPackCoding {
        HPackCoding {
            decoder: HPackDecode::new(size),
            encoder: HPackEncode::new(size),
        }
    }

    pub fn encoder(&mut self) -> &mut HPackEncode { &mut self.encoder }

    pub fn decoder(&mut self) -> &mut HPackDecode { &mut self.decoder }
}