use std::error::Error;
use std::fmt::{Display, Formatter};
use std::os::raw::c_int;
use crate::ffi;
use crate::ffi::CPointer;
use crate::boring::BoringResExt;

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
    ) -> c_int;
    fn DEFLATE_STREAM_compress(
        decoder: *mut DEFLATE_STREAM,
        data: *const u8,
        data_len: usize,
        out: *mut u8,
        out_len: *mut usize,
    ) -> c_int;
    fn DEFLATE_STREAM_flush(decoder: *mut DEFLATE_STREAM, out: *mut u8, out_len: *mut usize) -> c_int;
}
#[derive(Debug)]
pub enum DeflateError {
    NewDeflateDecoder,
    DeflateDecompressFailed,
    DeflateCompressFailed,
    DeflateFlushFailed,
}

impl Display for DeflateError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for DeflateError {}

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

    pub fn decompress(&self, data: &[u8], out: &mut [u8]) -> Result<usize, DeflateError> {
        let mut out_len = out.len();
        unsafe {
            DEFLATE_STREAM_decompress(
                self.stream.as_mut_ptr(),
                data.as_ptr(),
                data.len(),
                out.as_mut_ptr(),
                &mut out_len,
            )
        }.ok(DeflateError::DeflateDecompressFailed)?;
        Ok(out_len)
    }

    pub fn compress(&self, data: &[u8], out: &mut [u8]) -> Result<usize, DeflateError> {
        let mut out_len = out.len();
        unsafe {
            DEFLATE_STREAM_compress(
                self.stream.as_mut_ptr(),
                data.as_ptr(),
                data.len(),
                out.as_mut_ptr(),
                &mut out_len,
            )
        }.ok(DeflateError::DeflateCompressFailed)?;
        Ok(out_len)
    }

    pub fn flush(&self, out: &mut [u8]) -> Result<usize, DeflateError> {
        let mut out_len = out.len();
        unsafe { DEFLATE_STREAM_flush(self.stream.as_mut_ptr(), out.as_mut_ptr(), &mut out_len) }.ok(DeflateError::DeflateFlushFailed)?;
        Ok(out_len)
    }
}


#[cfg(test)]
mod zlib_ng_tests {
    use crate::coder;
    use crate::coder::deflate::DeflateStream;

    #[test]
    fn test_deflate() {
        let compressed = [109, 137, 177, 13, 0, 32, 12, 195, 206, 226, 161, 16, 85, 45, 19, 129, 129, 239, 169, 212, 181, 150, 23, 203, 2, 5, 198, 106, 112, 213, 51, 33, 104, 21, 233, 59, 227, 186, 246, 252];
        let decoder = DeflateStream::new_decompress(DeflateStream::DEFLATE).unwrap();
        let mut out = [0; 1024];
        let len1 = decoder.decompress(&compressed[..20], &mut out).unwrap();
        let len2 = decoder.decompress(&compressed[20..], &mut out[len1..]).unwrap();
        assert_eq!(&out[..len1 + len2], b"sdfsdfklllllllllllllllllllljsdfsdfkhsdkfhsdfsdfsdfyt7ujsre");


        let encoder = DeflateStream::new_compress(DeflateStream::DEFLATE).unwrap();
        let mut out = [0; 1024];
        let len1 = encoder.compress(b"sdfsdfklllllllllllllllllllljsdfsdfkhsdkfhsdfsdfsdfyt7ujsre", &mut out).unwrap();
        let len2 = encoder.flush(&mut out[len1..]).unwrap();
        assert_eq!(&out[..len1 + len2], [43, 78, 73, 43, 78, 73, 203, 206, 193, 2, 178, 138, 33, 114, 25, 197, 41, 217, 105, 25, 16, 78, 113, 74, 90, 101, 137, 121, 105, 86, 113, 81, 42, 0]);
        let res = coder::deflate_decompress(&out[..len1 + len2]).unwrap();
        assert_eq!(res, b"sdfsdfklllllllllllllllllllljsdfsdfkhsdkfhsdfsdfsdfyt7ujsre");
    }

    #[test]
    fn test_gzip() {
        let compressed = [31, 139, 8, 0, 0, 0, 0, 0, 0, 255, 109, 137, 177, 13, 0, 32, 12, 195, 206, 226, 161, 16, 85, 45, 19, 129, 129, 239, 169, 212, 181, 150, 23, 203, 2, 5, 198, 106, 112, 213, 51, 33, 104, 21, 233, 59, 227, 186, 246, 252, 93, 161, 13, 5, 58, 0, 0, 0];
        let decoder = DeflateStream::new_decompress(DeflateStream::GZIP).unwrap();
        let mut out = [0; 1024];
        let len = decoder.decompress(&compressed, &mut out).unwrap();
        assert_eq!(&out[..len], b"sdfsdfklllllllllllllllllllljsdfsdfkhsdkfhsdfsdfsdfyt7ujsre");


        let encoder = DeflateStream::new_compress(DeflateStream::GZIP).unwrap();
        let mut out = [0; 1024];
        let len1 = encoder.compress(b"sdfsdfklllllllllllllllllllljsdfsdfkhsdkfhsdfsdfsdfyt7ujsre", &mut out).unwrap();
        let len2 = encoder.flush(&mut out[len1..]).unwrap();
        assert_eq!(&out[..len1 + len2], [31, 139, 8, 0, 0, 0, 0, 0, 0, 10, 43, 78, 73, 43, 78, 73, 203, 206, 193, 2, 178, 138, 33, 114, 25, 197, 41, 217, 105, 25, 16, 78, 113, 74, 90, 101, 137, 121, 105, 86, 113, 81, 42, 0, 93, 161, 13, 5, 58, 0, 0, 0]);
        let res = coder::gzip_decompress(&out[..len1 + len2]).unwrap();
        assert_eq!(res, b"sdfsdfklllllllllllllllllllljsdfsdfkhsdkfhsdfsdfsdfyt7ujsre");
    }
}