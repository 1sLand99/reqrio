use crate::error::HlsResult;
pub use crate::hpack::encode2::HackEncode;
pub use error::HPackError;
pub use item::HPackItem;
pub use encode::HPackEncode;

mod encode;
mod error;
mod encode2;
mod item;
mod table;
mod index;
mod huffman;

pub struct HPackCoding {
    decoder: HackEncode,
    encoder: HPackEncode,
}

impl HPackCoding {
    pub fn new(size: usize) -> HPackCoding {
        HPackCoding {
            decoder: HackEncode::new_decode_size(size as u32),
            encoder: HPackEncode::new(size),
        }
    }

    pub fn decode(&mut self, context: &mut Vec<u8>) -> HlsResult<Vec<HPackItem>> {
        Ok(self.decoder.decode(context)?)
    }

    // pub fn encode(&mut self, headers: Vec<HeaderKey>) -> HlsResult<Vec<u8>> {
    //     self.encoder.encode(headers)
    // }

    pub fn encoder(&mut self) -> &mut HPackEncode { &mut self.encoder }

    pub fn decoder(&mut self) -> &mut HackEncode { &mut self.decoder }
}