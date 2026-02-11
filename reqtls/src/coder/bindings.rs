use std::os::raw::{c_int, c_void};

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct ZSTD_inBuffer {
    pub src: *const c_void,
    pub size: usize,
    pub pos: usize,
}

impl ZSTD_inBuffer {
    pub fn new_buf(buf: &[u8]) -> ZSTD_inBuffer {
        ZSTD_inBuffer {
            src: buf.as_ptr() as _,
            size: buf.len(),
            pos: 0,
        }
    }
}
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct ZSTD_outBuffer {
    pub dst: *mut c_void,
    pub size: usize,
    pub pos: usize,
}

impl ZSTD_outBuffer {
    pub fn new_buf(buf: &mut [u8]) -> ZSTD_outBuffer {
        ZSTD_outBuffer {
            dst: buf.as_mut_ptr() as _,
            size: buf.len(),
            pos: 0,
        }
    }
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct ZSTD_DStream {
    _unused: [u8; 0],
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct ZSTD_CStream {
    _unused: [u8; 0],
}


unsafe extern "C" {
    pub fn ZSTD_compress(
        dst: *mut c_void,
        dst_capacity: usize,
        src: *const c_void,
        src_size: usize,
        compression_level: i32,
    ) -> usize;

    pub fn ZSTD_decompress(
        dst: *mut c_void,
        dst_capacity: usize,
        src: *const c_void,
        src_size: usize,
    ) -> usize;

    pub fn ZSTD_compressBound(src_size: usize) -> usize;

    pub fn ZSTD_decompressBound(
        src: *const c_void,
        src_size: usize,
    ) -> usize;

    pub fn ZSTD_isError(code: usize) -> u32;

    pub fn ZSTD_createDStream() -> *mut ZSTD_DStream;
    pub fn ZSTD_freeDStream(zds: *mut ZSTD_DStream) -> usize;
    pub fn ZSTD_initDStream(zds: *mut ZSTD_DStream) -> usize;

    pub fn ZSTD_decompressStream(
        zds: *mut ZSTD_DStream,
        output: *mut ZSTD_outBuffer,
        input: *mut ZSTD_inBuffer,
    ) -> usize;

    pub fn ZSTD_createCStream() -> *mut ZSTD_CStream;
    pub fn ZSTD_freeCStream(zcs: *mut ZSTD_CStream) -> usize;
    pub fn ZSTD_initCStream(zcs: *mut ZSTD_CStream, level: c_int) -> usize;
    pub fn ZSTD_flushStream(
        zcs: *mut ZSTD_CStream,
        output: *mut ZSTD_outBuffer,
    ) -> usize;

    pub fn ZSTD_endStream(
        zcs: *mut ZSTD_CStream,
        output: *mut ZSTD_outBuffer,
    ) -> usize;

    pub fn ZSTD_compressStream(
        zcs: *mut ZSTD_CStream,
        output: *mut ZSTD_outBuffer,
        input: *mut ZSTD_inBuffer,
    ) -> usize;
}
