use crate::boring::BoringResExt;
use crate::coder::ext::{StreamDecode, StreamEncode};
use crate::ffi::{self, CPointer};
use std::error::Error;
use std::fmt::Display;
use std::os::raw::c_int;
use crate::{ReadExt, Reader, WriteExt};

#[derive(Debug)]
pub enum ZSTDError {
    NewDecoderFail,
    InitDecodeStreamFail,
    DecodeError,
    NewEncoderFail,
    InitEncoderStreamFail,
    EncodeError,
    FlushError,
}

impl Display for ZSTDError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for ZSTDError {}

#[repr(C)]
#[allow(non_camel_case_types)]
struct ZSTD_DECODER {
    _unused: [u8; 0],
}
ffi::c_pointer_free!(ZSTD_DECODER, ZSTD_DECODER_free);
#[repr(C)]
#[allow(non_camel_case_types)]
struct ZSTD_ENCODER {
    _unused: [u8; 0],
}
ffi::c_pointer_free!(ZSTD_ENCODER, ZSTD_ENCODER_free);

unsafe extern "C" {
    fn ZSTD_DECODER_new() -> *mut ZSTD_DECODER;
    fn ZSTD_DECODER_free(decoder: *mut ZSTD_ENCODER);
    fn ZSTD_DECODER_decompress(
        decoder: *const ZSTD_DECODER,
        data: *const u8,
        data_len: usize,
        out: *mut u8,
        out_len: *mut usize,
    ) -> c_int;

    fn ZSTD_ENCODER_new(level: i32) -> *mut ZSTD_ENCODER;
    fn ZSTD_ENCODER_free(encoder: *mut ZSTD_ENCODER);
    fn ZSTD_ENCODER_compress(
        encoder: *const ZSTD_ENCODER,
        data: *const u8,
        data_len: usize,
        out: *mut u8,
        out_len: *mut usize,
    ) -> c_int;
    fn ZSTD_ENCODER_flush(encoder: *const ZSTD_ENCODER, out: *mut u8, out_len: *mut usize) -> c_int;
}


pub struct ZstdDecoder(CPointer<ZSTD_DECODER>);

impl ZstdDecoder {
    pub fn new() -> Result<ZstdDecoder, ZSTDError> {
        let ptr = unsafe { ZSTD_DECODER_new() };
        let ptr = CPointer::new_checked(ptr, ZSTDError::NewDecoderFail)?;
        Ok(ZstdDecoder(ptr))
    }
}

impl<W: WriteExt> StreamDecode<W> for ZstdDecoder {
    type Error = ZSTDError;
    fn decompress(&mut self, reader: Reader<'_>, out: &mut W) -> Result<usize, ZSTDError> {
        println!("{}", reader.size());
        let mut out_len = out.unfilled_len();
        unsafe {
            ZSTD_DECODER_decompress(
                self.0.as_ptr(),
                reader.as_ptr(),
                reader.size(),
                out.unfilled_ptr(),
                &mut out_len,
            )
        }.ok(ZSTDError::DecodeError)?;
        println!("{}", out_len);
        out.add_len(out_len);
        Ok(0)
    }
}

pub struct ZstdEncoder(CPointer<ZSTD_ENCODER>);

impl ZstdEncoder {
    pub fn new() -> Result<ZstdEncoder, ZSTDError> {
        let ptr = unsafe { ZSTD_ENCODER_new(3) };
        let ptr = CPointer::new_checked(ptr, ZSTDError::NewEncoderFail)?;
        Ok(ZstdEncoder(ptr))
    }
}

impl StreamEncode for ZstdEncoder {
    type Error = ZSTDError;
    fn compress(&mut self, data: &[u8], out: &mut [u8]) -> Result<usize, ZSTDError> {
        let mut out_len = out.len();
        unsafe {
            ZSTD_ENCODER_compress(
                self.0.as_ptr(),
                data.as_ptr(),
                data.len(),
                out.as_mut_ptr(),
                &mut out_len,
            )
        }.ok(ZSTDError::EncodeError)?;
        Ok(out_len)
    }

    fn flush(&mut self, out: &mut [u8]) -> Result<usize, ZSTDError> {
        let mut out_len = out.len();
        unsafe {
            ZSTD_ENCODER_flush(
                self.0.as_ptr(),
                out.as_mut_ptr(),
                &mut out_len,
            )
        }.ok(ZSTDError::FlushError)?;
        Ok(out_len)
    }
}

#[cfg(test)]
mod zstd_tests {
    use crate::{coder, Buffer, ReadExt, Reader};
    use crate::coder::ext::{StreamDecode, StreamEncode};
    use crate::coder::zstd::{ZstdDecoder, ZstdEncoder};

    #[test]
    fn test_zstd() {
        let compressed = [40, 181, 47, 253, 32, 37, 41, 1, 0, 115, 100, 102, 104, 115, 100, 102, 115, 100, 103, 103, 106, 121, 117, 116, 101, 114, 100, 102, 116, 116, 104, 102, 103, 98, 104, 106, 104, 104, 103, 115, 100, 102, 103, 100, 103, 102];
        let mut decoder = ZstdDecoder::new().unwrap();
        let mut out = Buffer::with_capacity(1024);
        let mut reader = Reader::from_slice(&compressed);
        let len1 = decoder.decompress(reader.read_reader(20).unwrap(), &mut out).unwrap();
        let len2 = decoder.decompress(reader.read_reader(reader.unread_len()).unwrap(), &mut out).unwrap();
        assert_eq!(out.filled(), b"sdfhsdfsdggjyuterdftthfgbhjhhgsdfgdgf");


        let mut encoder = ZstdEncoder::new().unwrap();
        let mut out = [0; 1024];
        let len1 = encoder.compress(b"sdfhsdfsdggjyuterdftthfgbhjhhgsdfgdgf", &mut out).unwrap();
        let len2 = encoder.flush(&mut out[len1..]).unwrap();
        assert_eq!(coder::zstd_decompress(&out[..len1 + len2]).unwrap(), b"sdfhsdfsdggjyuterdftthfgbhjhhgsdfgdgf");
    }
}
