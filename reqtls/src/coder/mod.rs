#[cfg(feature = "zstd")]
mod zstd;
mod brotli;
#[cfg(feature = "zstd")]
pub(crate) mod bindings;
mod deflate;

use crate::error::RlsResult;
use crate::{BufferError, UrlError};
pub use brotli::{BrotliDecoder, BrotliEncoder, BrotliError};
pub use deflate::{DeflateError, DeflateStream};
use std::borrow::Cow;
#[cfg(feature = "zstd")]
pub use zstd::{ZSTDDecode, ZSTDEncode, ZSTDError};


#[cfg(feature = "zstd")]
pub fn zstd_compress(data: impl AsRef<[u8]>) -> Result<Vec<u8>, ZSTDError> {
    zstd::compress(data)
}

#[cfg(feature = "zstd")]
pub fn zstd_decompress(data: impl AsRef<[u8]>) -> Result<Vec<u8>, ZSTDError> {
    zstd::decompress(data)
}

pub fn url_encode<'a>(url: impl Into<Cow<'a, str>>) -> Cow<'a, str> {
    let url = url.into();
    match urlencoding::encode(url.as_ref()) {
        Cow::Borrowed(_) => url,
        Cow::Owned(v) => Cow::Owned(v),
    }
}

pub fn url_decode<'a>(url: impl Into<Cow<'a, str>>) -> Result<Cow<'a, str>, UrlError> {
    let url = url.into();
    match urlencoding::decode(url.as_ref())? {
        Cow::Borrowed(_) => Ok(url),
        Cow::Owned(v) => Ok(Cow::Owned(v)),
    }
}

pub fn br_decompress(buf: impl AsRef<[u8]>) -> Result<Vec<u8>, BrotliError> {
    let buf = buf.as_ref();
    let mut out = vec![0; buf.len() * 2];
    let mut decoder = BrotliDecoder::new()?;
    let len = loop {
        match decoder.decompress(buf, &mut out) {
            Ok(len) => break len,
            Err(BrotliError::Buffer(BufferError::CapacityTooSmall { .. })) => {
                out.resize(out.len() + 1024, 0);
            }
            Err(e) => return Err(e)
        };
    };
    out.truncate(len);
    Ok(out)
}

pub fn br_compress(buf: impl AsRef<[u8]>) -> Result<Vec<u8>, BrotliError> {
    let buf = buf.as_ref();
    let mut out = vec![0; buf.len()];
    let mut encoder = BrotliEncoder::new()?;
    let len1 = encoder.compress(buf, &mut out)?;
    let len2 = encoder.flush(&mut out[len1..])?;
    out.truncate(len1 + len2);
    Ok(out)
}


pub fn chunk_decode(mut raw: Vec<u8>) -> RlsResult<Vec<u8>> {
    let mut res = Vec::with_capacity(raw.len());
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

pub fn deflate_compress(buf: impl AsRef<[u8]>) -> Result<Vec<u8>, DeflateError> {
    let stream = DeflateStream::new_compress(DeflateStream::DEFLATE)?;
    let buf = buf.as_ref();
    let mut out = vec![0; buf.len()];
    let len1 = stream.compress(buf, &mut out)?;
    let len2 = stream.flush(&mut out[len1..])?;
    out.truncate(len1 + len2);
    Ok(out)
}

pub fn deflate_decompress(buf: impl AsRef<[u8]>) -> Result<Vec<u8>, DeflateError> {
    let buf = buf.as_ref();
    let stream = DeflateStream::new_decompress(DeflateStream::DEFLATE)?;
    let mut out = vec![0; buf.len() * 2];
    let len = stream.decompress(buf, &mut out)?;
    out.truncate(len);
    Ok(out)
}

pub fn gzip_compress(buf: impl AsRef<[u8]>) -> RlsResult<Vec<u8>> {
    let stream = DeflateStream::new_compress(DeflateStream::GZIP)?;
    let buf = buf.as_ref();
    let mut out = vec![0; buf.len()];
    let len1 = stream.compress(buf, &mut out)?;
    let len2 = stream.flush(&mut out[len1..])?;
    out.truncate(len1 + len2);
    Ok(out)
}

pub fn gzip_decompress(buf: impl AsRef<[u8]>) -> RlsResult<Vec<u8>> {
    let buf = buf.as_ref();
    if buf.is_empty() { return Ok(vec![]); }
    let stream = DeflateStream::new_decompress(DeflateStream::GZIP)?;
    let mut out = vec![0; buf.len() * 2];
    let len = stream.decompress(buf, &mut out)?;
    out.truncate(len);
    Ok(out)
}
