pub use decode::HPackDecode;
pub use encode::HPackEncode;

mod encode;
mod decode;
mod table;
mod index;

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