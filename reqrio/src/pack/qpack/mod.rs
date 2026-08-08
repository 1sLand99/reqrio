mod table;
mod index;
mod decode;

#[derive(Copy, Clone)]
pub enum QPackType {
    Stream,
    StreamEncoder,
    StreamDecoder,
}