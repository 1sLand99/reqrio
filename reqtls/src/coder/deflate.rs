use crate::coder::ext::{StreamDecode, StreamEncode};
use crate::ffi::CPointer;
use crate::{ffi, Buffer, ReadExt, Reader, WriteExt};
use std::error::Error;
use std::fmt::{Display, Formatter};

#[repr(C)]
#[allow(non_camel_case_types)]
struct DEFLATE_STREAM {
    _unused: [u8; 0],
}
ffi::c_pointer_free!(DEFLATE_STREAM, DEFLATE_STREAM_free);

unsafe extern "C" {
    fn DEFLATE_STREAM_new(enc: i32, level: i32, wbits: i32) -> *mut DEFLATE_STREAM;
    fn DEFLATE_STREAM_free(decoder: *mut DEFLATE_STREAM);
    fn DEFLATE_STREAM_decompress(
        decoder: *mut DEFLATE_STREAM,
        data: *const u8,
        data_len: usize,
        out: *mut u8,
        out_len: *mut usize,
    ) -> DeflateState;
    fn DEFLATE_STREAM_compress(
        decoder: *mut DEFLATE_STREAM,
        data: *const u8,
        data_len: usize,
        out: *mut u8,
        out_len: *mut usize,
    ) -> DeflateState;
    fn DEFLATE_STREAM_flush(decoder: *mut DEFLATE_STREAM, out: *mut u8, out_len: *mut usize) -> DeflateState;
}
#[derive(Debug)]
pub enum DeflateError {
    NewDeflateDecoder,
    DeflateDecompressFailed,
    DeflateCompressFailed,
    DeflateFlushFailed,
    Error(DeflateState),
}

impl Display for DeflateError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for DeflateError {}


#[repr(C)]
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum DeflateState {
    OK = 0,
    STREAM_END = 1,
    NEED_DICT = 2,
    Errno = -1,
    STREAM_ERROR = -2,
    DATA_ERROR = -3,
    MEM_ERROR = -4,
    BUF_ERROR = -5,
    VERSION_ERROR = -6,
}

pub struct DeflateStream {
    stream: CPointer<DEFLATE_STREAM>,
}

impl DeflateStream {
    pub const DEFLATE: i32 = -15;
    pub const ZLIB: i32 = 15;
    pub const GZIP: i32 = 31;
    pub fn new(enc: i32, level: i32, wbits: i32) -> Result<DeflateStream, DeflateError> {
        let ptr = unsafe { DEFLATE_STREAM_new(enc, level, wbits) };
        let ptr = CPointer::new_checked(ptr, DeflateError::NewDeflateDecoder)?;
        Ok(DeflateStream {
            stream: ptr
        })
    }

    pub fn new_compress(wbits: i32) -> Result<DeflateStream, DeflateError> {
        DeflateStream::new(1, -1, wbits)
    }

    pub fn new_decompress(wbits: i32) -> Result<DeflateStream, DeflateError> {
        DeflateStream::new(0, 0, wbits)
    }


    pub fn decompress_once<'a>(&mut self, reader: &mut Reader<'a>, out: &mut Vec<u8>) -> Result<usize, DeflateError> {
        let mut wrote = 0;
        loop {
            let mut writer = Buffer::from_ptr(out);
            writer.add_len(wrote);
            let res = if reader.unread_len() == 0 {
                self.flush(&mut writer)
            } else { self.decompress(reader, &mut writer) };
            wrote = writer.filled().len();
            match res {
                Ok(_) => return Ok(writer.filled().len()),
                Err(DeflateError::Error(DeflateState::BUF_ERROR)) => {
                    out.resize(out.len() + 1024, 0);
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn flush<W: WriteExt>(&mut self, out: &mut W) -> Result<(), DeflateError> {
        let mut out_len = out.unfilled_len();
        let state = unsafe { DEFLATE_STREAM_flush(self.stream.as_mut_ptr(), out.unfilled_ptr(), &mut out_len) };
        if !matches!(state, DeflateState::OK|DeflateState::STREAM_END) {
            return Err(DeflateError::Error(state));
        }
        out.add_len(out_len);
        Ok(())
    }
}

impl<W: WriteExt> StreamDecode<W> for DeflateStream {
    type Error = DeflateError;
    fn decompress(&mut self, reader: &mut Reader<'_>, out: &mut W) -> Result<(), DeflateError> {
        let mut out_len = out.unfilled_len();
        let state = unsafe {
            DEFLATE_STREAM_decompress(
                self.stream.as_mut_ptr(),
                reader.unread_ptr(),
                reader.unread_len(),
                out.unfilled_ptr(),
                &mut out_len,
            )
        };
        reader.add_len(reader.unread_len());
        out.add_len(out_len);
        if !matches!(state, DeflateState::OK|DeflateState::STREAM_END) {
            return Err(DeflateError::Error(state));
        }
        Ok(())
    }
}

impl StreamEncode for DeflateStream {
    type Error = DeflateError;
    fn compress(&mut self, data: &[u8], out: &mut [u8]) -> Result<usize, DeflateError> {
        let mut out_len = out.len();
        let state = unsafe {
            DEFLATE_STREAM_compress(
                self.stream.as_mut_ptr(),
                data.as_ptr(),
                data.len(),
                out.as_mut_ptr(),
                &mut out_len,
            )
        };
        if !matches!(state, DeflateState::OK|DeflateState::STREAM_END) {
            return Err(DeflateError::Error(state));
        }
        Ok(out_len)
    }

    fn finalize(&mut self, out: &mut [u8]) -> Result<usize, DeflateError> {
        let mut writer = Buffer::from_ptr(out.as_mut());
        self.flush(&mut writer)?;
        Ok(writer.len())
    }
}


#[cfg(test)]
mod zlib_ng_tests {
    use crate::coder::deflate::DeflateStream;
    use crate::coder::ext::{StreamDecode, StreamEncode};
    use crate::{coder, Buffer, Reader, WriteExt};

    #[test]
    fn test_deflate() {
        let compressed = [109, 137, 177, 13, 0, 32, 12, 195, 206, 226, 161, 16, 85, 45, 19, 129, 129, 239, 169, 212, 181, 150, 23, 203, 2, 5, 198, 106, 112, 213, 51, 33, 104, 21, 233, 59, 227, 186, 246, 252];
        let mut decoder = DeflateStream::new_decompress(DeflateStream::DEFLATE).unwrap();
        let mut out = Buffer::with_capacity(1024);
        let mut reader = Reader::from_slice(&compressed);
        decoder.decompress(&mut reader, &mut out).unwrap();
        // decoder.decompress(reader.read_reader(reader.unread_len()).unwrap(), &mut out).unwrap();
        assert_eq!(out.filled(), b"sdfsdfklllllllllllllllllllljsdfsdfkhsdkfhsdfsdfsdfyt7ujsre");


        let mut encoder = DeflateStream::new_compress(DeflateStream::DEFLATE).unwrap();
        let mut out = [0; 1024];
        let len1 = encoder.compress(b"sdfsdfklllllllllllllllllllljsdfsdfkhsdkfhsdfsdfsdfyt7ujsre", &mut out).unwrap();
        let len2 = encoder.finalize(&mut out[len1..]).unwrap();
        assert_eq!(&out[..len1 + len2], [43, 78, 73, 43, 78, 73, 203, 206, 193, 2, 178, 138, 33, 114, 25, 197, 41, 217, 105, 25, 16, 78, 113, 74, 90, 101, 137, 121, 105, 86, 113, 81, 42, 0]);
        let res = coder::deflate_decompress(&out[..len1 + len2]).unwrap();
        assert_eq!(res, b"sdfsdfklllllllllllllllllllljsdfsdfkhsdkfhsdfsdfsdfyt7ujsre");
    }

    #[test]
    fn test_gzip() {
        let compressed = [31, 139, 8, 0, 0, 0, 0, 0, 0, 255, 109, 137, 177, 13, 0, 32, 12, 195, 206, 226, 161, 16, 85, 45, 19, 129, 129, 239, 169, 212, 181, 150, 23, 203, 2, 5, 198, 106, 112, 213, 51, 33, 104, 21, 233, 59, 227, 186, 246, 252, 93, 161, 13, 5, 58, 0, 0, 0];
        let mut decoder = DeflateStream::new_decompress(DeflateStream::GZIP).unwrap();
        let mut out = vec![0; 1];
        let mut writer = Buffer::from_ptr(out.as_mut());
        let mut reader = Reader::from_slice(&compressed);
        let res = decoder.decompress(&mut reader, &mut writer);
        assert!(res.is_err());
        out.resize(1024, 0);
        let wrote = writer.filled().len();
        let mut writer = Buffer::from_ptr(out.as_mut());
        writer.add_len(wrote);
        decoder.flush(&mut writer).unwrap();
        assert_eq!(writer.filled(), b"sdfsdfklllllllllllllllllllljsdfsdfkhsdkfhsdfsdfsdfyt7ujsre");


        let mut encoder = DeflateStream::new_compress(DeflateStream::GZIP).unwrap();
        let mut out = [0; 1024];
        let len1 = encoder.compress(b"sdfsdfklllllllllllllllllllljsdfsdfkhsdkfhsdfsdfsdfyt7ujsre", &mut out).unwrap();
        let len2 = encoder.finalize(&mut out[len1..]).unwrap();
        assert_eq!(&out[..len1 + len2], [31, 139, 8, 0, 0, 0, 0, 0, 0, 10, 43, 78, 73, 43, 78, 73, 203, 206, 193, 2, 178, 138, 33, 114, 25, 197, 41, 217, 105, 25, 16, 78, 113, 74, 90, 101, 137, 121, 105, 86, 113, 81, 42, 0, 93, 161, 13, 5, 58, 0, 0, 0]);
        let res = coder::gzip_decompress(&out[..len1 + len2]).unwrap();
        assert_eq!(res, b"sdfsdfklllllllllllllllllllljsdfsdfkhsdkfhsdfsdfsdfyt7ujsre");
    }
}