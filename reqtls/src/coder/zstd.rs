use super::bindings::*;
use crate::ffi::CPointer;
use std::error::Error;
use std::fmt::Display;
use std::os::raw::c_void;

#[derive(Debug)]
pub enum ZSTDError {
    NewDecoderFail,
    InitDecodeStreamFail,
    DecodeError,
    NewEncoderFail,
    InitEncoderStreamFail,
    EncodeError,
    FinalizeError,
}

impl Display for ZSTDError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for ZSTDError {}

pub struct ZSTDDecode {
    stream: CPointer<ZSTD_DStream>,
    buffer: [u8; 4096],
    len: usize,
}

impl ZSTDDecode {
    pub fn new() -> Result<ZSTDDecode, ZSTDError> {
        let stream = CPointer::new_checked(unsafe { ZSTD_createDStream() }, ZSTDError::NewDecoderFail)?;
        let ret = unsafe { ZSTD_isError(ZSTD_initDStream(stream.as_mut_ptr())) };
        if ret != 0 { return Err(ZSTDError::InitDecodeStreamFail); }
        Ok(ZSTDDecode {
            stream,
            buffer: [0; 4096],
            len: 0,
        })
    }

    pub fn decode(&mut self, data: &[u8]) -> Result<&[u8], ZSTDError> {
        self.len = 0;
        let mut buf_in = ZSTD_inBuffer::new_buf(data);
        while buf_in.pos < buf_in.size {
            let mut buf_out = ZSTD_outBuffer::new_buf(&mut self.buffer);
            let ret = unsafe { ZSTD_decompressStream(self.stream.as_mut_ptr(), &mut buf_out, &mut buf_in) };
            if unsafe { ZSTD_isError(ret) } != 0 { return Err(ZSTDError::DecodeError); }
            self.len += buf_out.pos;
            if ret == 0 { break; }
        }
        Ok(&self.buffer[..self.len])
    }
}

pub struct ZSTDEncode {
    stream: CPointer<ZSTD_CStream>,
    buffer: [u8; 4096],
    len: usize,
}

impl ZSTDEncode {
    pub fn new() -> Result<ZSTDEncode, ZSTDError> {
        let stream = CPointer::new_checked(unsafe { ZSTD_createCStream() }, ZSTDError::NewEncoderFail)?;
        let ret = unsafe { ZSTD_isError(ZSTD_initCStream(stream.as_mut_ptr(), 3)) };
        if ret != 0 { return Err(ZSTDError::InitEncoderStreamFail); }
        Ok(ZSTDEncode {
            stream,
            buffer: [0; 4096],
            len: 0,
        })
    }

    pub fn encode(&mut self, data: &[u8]) -> Result<&[u8], ZSTDError> {
        self.len = 0;
        let mut buf_in = ZSTD_inBuffer::new_buf(data);
        while buf_in.pos < buf_in.size {
            let mut buf_out = ZSTD_outBuffer::new_buf(&mut self.buffer);
            let ret = unsafe { ZSTD_compressStream(self.stream.as_mut_ptr(), &mut buf_out, &mut buf_in) };
            if unsafe { ZSTD_isError(ret) } != 0 { return Err(ZSTDError::EncodeError); }
            unsafe { ZSTD_flushStream(self.stream.as_mut_ptr(), &mut buf_out); }
            self.len += buf_out.pos;
            if ret == 0 { break; }
        }
        Ok(&self.buffer[..self.len])
    }

    pub fn finalize(&mut self) -> Result<&[u8], ZSTDError> {
        self.len = 0;
        loop {
            let mut buf_out = ZSTD_outBuffer::new_buf(&mut self.buffer);
            let ret = unsafe { ZSTD_endStream(self.stream.as_mut_ptr(), &mut buf_out) };
            if unsafe { ZSTD_isError(ret) } != 0 { return Err(ZSTDError::FinalizeError); }
            self.len += buf_out.pos;
            if ret == 0 { break; }
        }
        Ok(&self.buffer[..self.len])
    }
}


pub fn compress(data: impl AsRef<[u8]>) -> Result<Vec<u8>, ZSTDError> {
    let bound = unsafe { ZSTD_compressBound(data.as_ref().len()) };
    let mut buffer = vec![0u8; bound];
    let size = unsafe {
        ZSTD_compress(
            buffer.as_mut_ptr() as *mut c_void,
            bound,
            data.as_ref().as_ptr() as _,
            data.as_ref().len(),
            3,
        )
    };
    if unsafe { ZSTD_isError(size) } != 0 { return Err(ZSTDError::EncodeError); }
    buffer.truncate(size);
    Ok(buffer)
}

pub fn decompress(data: impl AsRef<[u8]>) -> Result<Vec<u8>, ZSTDError> {
    let bound = unsafe { ZSTD_decompressBound(data.as_ref().as_ptr() as _, data.as_ref().len()) };
    if bound == 0 { return Err(ZSTDError::DecodeError); }
    let mut buffer = vec![0u8; bound];
    let len = unsafe {
        ZSTD_decompress(
            buffer.as_mut_ptr() as _,
            bound,
            data.as_ref().as_ptr() as _,
            data.as_ref().len(),
        )
    };
    if unsafe { ZSTD_isError(len) } != 0 { return Err(ZSTDError::DecodeError); }
    buffer.truncate(len);
    Ok(buffer)
}