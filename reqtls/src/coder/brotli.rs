use std::error::Error;
use std::ffi::c_int;
use std::fmt::{Display, Formatter};
use crate::ffi::CPointer;
use crate::{ffi, BufferError, Reader, WriteExt};
use crate::coder::ext::{StreamDecode, StreamEncode};

#[repr(C)]
#[allow(non_camel_case_types)]
struct BROTLI_DECODER {
    _unused: [u8; 0],
}
ffi::c_pointer_free!(BROTLI_DECODER, BROTLI_DECODER_free);

#[repr(C)]
#[allow(non_camel_case_types)]
struct BROTLI_ENCODER {
    _unused: [u8; 0],
}
ffi::c_pointer_free!(BROTLI_ENCODER, BROTLI_ENCODER_free);

unsafe extern "C" {
    fn BROTLI_DECODER_new() -> *mut BROTLI_DECODER;
    fn BROTLI_DECODER_free(decoder: *mut BROTLI_DECODER);
    fn BROTLI_DECODER_decompress(
        decoder: *const BROTLI_DECODER,
        in_: *const u8,
        in_len: *mut usize,
        out: *mut u8,
        out_len: *mut usize,
        total: *mut usize,
    ) -> BrotliState;
    fn BROTLI_ENCODER_new(quality: u32, lg_win: u32) -> *mut BROTLI_ENCODER;
    fn BROTLI_ENCODER_free(encoder: *mut BROTLI_ENCODER);
    fn BROTLI_ENCODER_compress(
        encoder: *const BROTLI_ENCODER,
        in_: *const u8,
        in_len: *mut usize,
        out: *mut u8,
        out_len: *mut usize,
        total: *mut usize,
    ) -> c_int;
    fn BROTLI_ENCODER_flush(
        encoder: *const BROTLI_ENCODER,
        out: *mut u8,
        out_len: *mut usize,
        total: *mut usize,
    ) -> c_int;
}

#[repr(C)]
#[derive(Debug, PartialEq)]
#[allow(unused)]
enum BrotliState {
    Error = 0,
    Finish = 1,
    Continue = 2,
    BufferTooSmall = 3,
}

#[derive(Debug)]
pub enum BrotliError {
    NewDecoderError,
    DecompressFail,
    CompressFail,
    FlushFail,
    Buffer(BufferError),
}

impl Display for BrotliError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl Error for BrotliError {}

impl From<BufferError> for BrotliError {
    fn from(value: BufferError) -> Self {
        BrotliError::Buffer(value)
    }
}


pub struct BrotliDecoder {
    ptr: CPointer<BROTLI_DECODER>,
    total_len: usize,
}

impl BrotliDecoder {
    pub fn new() -> Result<BrotliDecoder, BrotliError> {
        let ptr = unsafe { BROTLI_DECODER_new() };
        let ptr = CPointer::new_checked(ptr, BrotliError::NewDecoderError)?;
        Ok(BrotliDecoder {
            ptr,
            total_len: 0,
        })
    }
}

impl<W: WriteExt> StreamDecode<W> for BrotliDecoder {
    type Error = BrotliError;
    fn decompress(&mut self, reader: Reader<'_>, out: &mut W) -> Result<usize, BrotliError> {
        let buf = reader.into_inner();
        let mut remain_in_size = buf.len();
        let mut remain_buffer_size = out.unfilled_len();
        while remain_in_size > 0 {
            let res = unsafe {
                BROTLI_DECODER_decompress(
                    self.ptr.as_ptr(),
                    buf.as_ptr(),
                    &mut remain_in_size,
                    out.unfilled_ptr(),
                    &mut remain_buffer_size,
                    &mut self.total_len,
                )
            };
            match res {
                BrotliState::Error => return Err(BrotliError::DecompressFail),
                BrotliState::Finish => { break; }
                BrotliState::Continue => continue,
                BrotliState::BufferTooSmall => return Err(BufferError::CapacityTooSmall {
                    needed: out.len() + remain_in_size,
                    current: out.len(),
                }.into())
            }
        }
        assert_eq!(remain_in_size, 0);
        out.add_len(out.unfilled_len() - remain_buffer_size);
        Ok(0)
    }
}

pub struct BrotliEncoder {
    ptr: CPointer<BROTLI_ENCODER>,
    total_len: usize,
}

impl BrotliEncoder {
    pub fn new() -> Result<BrotliEncoder, BrotliError> {
        let ptr = unsafe { BROTLI_ENCODER_new(11, 22) };
        let ptr = CPointer::new_checked(ptr, BrotliError::NewDecoderError)?;
        Ok(BrotliEncoder {
            ptr,
            total_len: 0,
        })
    }
}


impl StreamEncode for BrotliEncoder {
    type Error = BrotliError;
    fn compress(&mut self, buf: &[u8], out: &mut [u8]) -> Result<usize, BrotliError> {
        let mut remain_in_size = buf.len();
        let mut remain_buffer_size = out.len();
        let ret = unsafe {
            BROTLI_ENCODER_compress(
                self.ptr.as_ptr(),
                buf.as_ptr(),
                &mut remain_in_size,
                out.as_mut_ptr(),
                &mut remain_buffer_size,
                &mut self.total_len,
            )
        };
        if ret != 1 { return Err(BrotliError::CompressFail); }
        assert_eq!(remain_in_size, 0);
        Ok(out.len() - remain_buffer_size)
    }

    fn flush(&mut self, out: &mut [u8]) -> Result<usize, BrotliError> {
        let mut remain_buffer_size = out.len();
        let ret = unsafe {
            BROTLI_ENCODER_flush(
                self.ptr.as_ptr(),
                out.as_mut_ptr(),
                &mut remain_buffer_size,
                &mut self.total_len,
            )
        };
        if ret != 1 { return Err(BrotliError::FlushFail); }
        Ok(out.len() - remain_buffer_size)
    }
}

#[cfg(test)]
mod brotli_test {
    use crate::{coder, Buffer, ReadExt, Reader};
    use crate::coder::brotli::{BrotliDecoder, BrotliEncoder};
    use crate::coder::ext::{StreamDecode, StreamEncode};

    #[test]
    fn test_brotli_decoder() {
        let mut decode = BrotliDecoder::new().unwrap();
        let mut decompressed = Buffer::with_capacity(1024);
        let compressed = [27, 59, 0, 248, 197, 109, 108, 188, 35, 42, 217, 147, 70, 37, 10, 74, 145, 67, 2, 167, 136, 88, 56, 154, 148, 111, 44, 175, 176, 152, 63, 84, 220, 226, 158, 42, 46, 44, 40, 152, 60, 14];
        let mut reader = Reader::from_slice(&compressed);
        decode.decompress(reader.read_reader(20).unwrap(), &mut decompressed).unwrap();
        decode.decompress(reader.read_reader(reader.unread_len()).unwrap(), &mut decompressed).unwrap();
        assert_eq!(&decompressed.filled(), b"dfjsdkgfsdhkgjksfyhdlfusdhgfkyudsgflsduyfgsdukfsdfgdhfgjhjhk");
        let de = coder::br_decompress(compressed).unwrap();
        assert_eq!(de, b"dfjsdkgfsdhkgjksfyhdlfusdhgfkyudsgflsduyfgsdukfsdfgdhfgjhjhk");
    }

    #[test]
    fn test_brotli_encoder() {
        let text = "dfjsdkgfsdhkgjksfyhdlfusdhgfkyudsgflsduyfgsdukfsdfgdhfgjhjhk";
        let mut encoder = BrotliEncoder::new().unwrap();
        let mut compressed = vec![0; 1024];
        let len1 = encoder.compress(text.as_bytes(), compressed.as_mut()).unwrap();
        let len2 = encoder.flush(&mut compressed[len1..]).unwrap();
        assert_eq!(len1 + len2, 42);
        assert_eq!(&compressed[..len1 + len2], [27, 59, 0, 248, 197, 109, 108, 188, 35, 42, 217, 147, 70, 37, 10, 74, 145, 67, 2, 167, 136, 88, 56, 154, 148, 111, 44, 175, 176, 152, 63, 84, 220, 226, 158, 42, 46, 44, 40, 152, 60, 14]);
        assert_eq!(coder::br_compress(text).unwrap(), [27, 59, 0, 248, 197, 109, 108, 188, 35, 42, 217, 147, 70, 37, 10, 74, 145, 67, 2, 167, 136, 88, 56, 154, 148, 111, 44, 175, 176, 152, 63, 84, 220, 226, 158, 42, 46, 44, 40, 152, 60, 14]);


        let mut decompressed = Buffer::with_capacity(1024);
        let mut decode = BrotliDecoder::new().unwrap();
        let reader = Reader::from_slice(&compressed[..len1 + len2]);
        decode.decompress(reader, &mut decompressed).unwrap();
        assert_eq!(decompressed.filled(), b"dfjsdkgfsdhkgjksfyhdlfusdhgfkyudsgflsduyfgsdukfsdfgdhfgjhjhk");
    }
}