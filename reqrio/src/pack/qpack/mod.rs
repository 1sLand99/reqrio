mod table;
mod index;
mod decode;
mod encode;

pub use encode::QPackEncode;
pub use decode::QPackDecode;

#[derive(Copy, Clone)]
pub enum QPackType {
    Stream,
    StreamEncoder,
    StreamDecoder,
}