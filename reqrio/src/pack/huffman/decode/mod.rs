use crate::error::HlsResult;
use reader::DecodeReader;
mod reader;
mod table;

pub fn decode(src: impl AsRef<[u8]>) -> HlsResult<Vec<u8>> {
    let mut reader = DecodeReader::new();
    let mut dst = vec![];
    for byte in src.as_ref() {
        reader.decode(*byte, &mut dst)?;
    }
    reader.finalize(&mut dst)?;
    Ok(dst)
}