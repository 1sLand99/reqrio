use std::borrow::Cow;
use std::io::BufReader;
use std::io::Read;
use flate2::Compression;
use flate2::read::{DeflateDecoder, DeflateEncoder, GzDecoder, GzEncoder};
use crate::error::RlsResult;
#[cfg(feature = "zstd")]
pub use zstd::{ZSTDDecode, ZSTDEncode};

#[cfg(feature = "zstd")]
mod zstd;
#[cfg(feature = "zstd")]
pub(crate) mod bindings;

#[cfg(feature = "zstd")]
pub fn zstd_compress(data: impl AsRef<[u8]>) -> RlsResult<Vec<u8>> {
    zstd::compress(data)
}

#[cfg(feature = "zstd")]
pub fn zstd_decompress(data: impl AsRef<[u8]>) -> RlsResult<Vec<u8>> {
    zstd::decompress(data)
}

pub fn url_encode(url: &impl AsRef<str>) -> Cow<'_, str> {
    urlencoding::encode(url.as_ref())
}

pub fn url_decode(url: &impl AsRef<str>) -> RlsResult<Cow<'_, str>> {
    Ok(urlencoding::decode(url.as_ref())?)
}

pub fn br_decompress(brd: impl AsRef<[u8]>) -> RlsResult<Vec<u8>> {
    let mut buffer = BufReader::new(brd.as_ref());
    let mut out = vec![];
    brotli::BrotliDecompress(&mut buffer, &mut out)?;
    Ok(out)
}

pub fn br_compress(brd: impl AsRef<[u8]>) -> RlsResult<Vec<u8>> {
    let params = brotli::enc::BrotliEncoderParams::default();
    let mut bufread = BufReader::new(brd.as_ref());
    let mut out = vec![];
    brotli::BrotliCompress(&mut bufread, &mut out, &params)?;
    Ok(out)
}


pub fn chunk_decode(mut raw: Vec<u8>) -> RlsResult<Vec<u8>> {
    let mut res = vec![];
    while let Some(pos) = raw.windows(2).position(|w| w == b"\r\n") {
        let len_bs = raw.drain(..pos).collect();
        let len_str = String::from_utf8(len_bs)?;
        //删除\r\n
        raw.drain(..2);
        let chunk_len = usize::from_str_radix(len_str.as_str(), 16)?;
        res.extend(raw.drain(..chunk_len).collect::<Vec<_>>());
        //删除\r\n
        raw.drain(..2);
    }
    Ok(res)
}

pub fn deflate_compress(ded: impl AsRef<[u8]>) -> RlsResult<Vec<u8>> {
    let mut de = DeflateEncoder::new(ded.as_ref(), Compression::default());
    let mut out = vec![];
    de.read_to_end(&mut out)?;
    Ok(out)
}

pub fn deflate_decompress(ded: impl AsRef<[u8]>) -> RlsResult<Vec<u8>> {
    let mut de = DeflateDecoder::new(ded.as_ref());
    let mut out = vec![];
    de.read_to_end(&mut out)?;
    Ok(out)
}

pub fn gzip_compress(ded: impl AsRef<[u8]>) -> RlsResult<Vec<u8>> {
    let mut ge = GzEncoder::new(ded.as_ref(), Compression::default());
    let mut out = vec![];
    ge.read_to_end(&mut out)?;
    Ok(out)
}

pub fn gzip_decompress(ded: impl AsRef<[u8]>) -> RlsResult<Vec<u8>> {
    if ded.as_ref().is_empty() { return Ok(vec![]); }
    let mut gd = GzDecoder::new(ded.as_ref());
    let mut out = vec![];
    gd.read_to_end(&mut out)?;
    Ok(out)
}
