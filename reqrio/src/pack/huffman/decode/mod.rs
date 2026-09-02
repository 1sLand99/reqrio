use reader::DecodeReader;
use crate::pack::PackError;

mod reader;
mod table;

pub fn decode(src: impl AsRef<[u8]>) -> Result<Vec<u8>, PackError> {
    let mut reader = DecodeReader::new();
    let mut dst = vec![];
    for byte in src.as_ref() {
        reader.decode(*byte, &mut dst)?;
    }
    reader.finalize(&mut dst)?;
    Ok(dst)
}