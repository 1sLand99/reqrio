use crate::buffer::*;
use crate::error::RlsResult;
use crate::{Buffer, BufferError, Reader, RlsError};
#[cfg(feature = "log")]
use log::warn;
use std::ffi::CString;
use std::ops::Range;
use std::slice;
use std::str::Utf8Error;

#[allow(non_camel_case_types)]
pub type u24 = u32;

pub trait WriteExt {
    fn buffer(&self) -> &Buffer;
    fn buffer_mut(&mut self) -> &mut Buffer;

    fn capacity(&self) -> usize {
        unsafe { Buffer_capacity(self.buffer().0.as_ptr()) }
    }
    fn check_write(&self, res: i32, size: usize) -> Result<(), BufferError> {
        if res == 1 { return Ok(()); };
        Err(BufferError::CapacityTooSmall {
            current: self.capacity(),
            needed: self.capacity() + size,
        })
    }

    fn write_u8(&mut self, v: u8) -> Result<(), BufferError> {
        let res = unsafe { Buffer_write_u8(self.buffer_mut().0.as_mut_ptr(), &v) };
        self.check_write(res, 1)
    }
    fn write_u16_be(&mut self, v: u16) -> Result<(), BufferError> {
        let res = unsafe { Buffer_write_u16(self.buffer_mut().0.as_mut_ptr(), &v) };
        self.check_write(res, 2)
    }

    #[inline]
    fn write_u16(&mut self, v: u16) -> Result<(), BufferError> {
        self.write_u16_be(v.to_be())
    }

    fn write_u24_be(&mut self, v: u24) -> Result<(), BufferError> {
        let res = unsafe { Buffer_write_u24(self.buffer_mut().0.as_mut_ptr(), &v) };
        self.check_write(res, 3)
    }

    #[inline]
    fn write_u24(&mut self, v: u24) -> Result<(), BufferError> {
        self.write_u24_be(v.to_be())
    }

    fn write_u24_be_in(&mut self, place: usize, v: u24) -> Result<usize, BufferError> {
        let res = unsafe { Buffer_write_u24_in(self.buffer_mut().0.as_mut_ptr(), place, &v) };
        self.check_write(res, 3)?;
        Ok(3)
    }

    fn write_u24_in(&mut self, place: usize, v: u24) -> Result<usize, BufferError> {
        self.write_u24_be_in(place, v.to_be())
    }

    fn write_u32_be(&mut self, v: u32) -> Result<(), BufferError> {
        let res = unsafe { Buffer_write_u32(self.buffer_mut().0.as_mut_ptr(), &v) };
        self.check_write(res, 4)
    }

    #[inline]
    fn write_u32(&mut self, v: u32) -> Result<(), BufferError> {
        self.write_u32_be(v.to_be())
    }

    #[inline]
    fn write_ru32(&mut self, v: &u32) -> Result<(), BufferError> {
        self.write_u32_be(v.to_be())
    }

    fn write_slice(&mut self, v: &[u8]) -> Result<(), BufferError> {
        let res = unsafe { Buffer_write_slice(self.buffer_mut().0.as_mut_ptr(), v.as_ptr(), v.len()) };
        self.check_write(res, v.len())
    }

    ///不更新长度，需要更新使用write_slice
    fn write_slice_in(&mut self, place: usize, v: &[u8]) -> Result<usize, BufferError> {
        let res = unsafe { Buffer_write_slice_in(self.buffer_mut().0.as_mut_ptr(), place, v.as_ptr(), v.len()) };
        self.check_write(res, v.len())?;
        Ok(v.len())
    }


    fn flush(&mut self, offset: usize, sni: String, h2: bool) -> RlsResult<()> {
        let csni = CString::new(sni)?;
        let res = unsafe { Buffer_flush(self.buffer_mut().0.as_mut_ptr(), self.offset().end - offset, csni.as_ptr(), h2) };
        if res != 1 { return Err(RlsError::Currently("buffer flush error".to_string())); }
        Ok(())
    }

    fn check_subscription(token: impl AsRef<str>) -> RlsResult<i32> {
        let is_subscribed = unsafe { is_subscription(CString::new(token.as_ref())?.as_ptr()) };
        if !is_subscribed {
            #[cfg(feature = "log")]
            warn!("[Fingerprint] You have not subscribed yet, so this call will be ignored.");
            #[cfg(not(feature = "log"))]
            println!("\x1b[01;33m[Fingerprint] WARN \x1b[0m You have not subscribed yet, so this call will be ignored.");
        }
        Ok(if is_subscribed { 0 } else { -2 })
    }

    #[inline]
    fn unfilled_len(&self) -> usize {
        let capacity = unsafe { Buffer_capacity(self.buffer().0.as_ptr()) };
        capacity - self.end()
    }

    #[inline]
    fn start(&self) -> usize {
        unsafe { Buffer_start(self.buffer().0.as_ptr()) }
    }

    #[inline]
    fn end(&self) -> usize {
        unsafe { Buffer_end(self.buffer().0.as_ptr()) }
    }

    #[inline]
    fn unfilled_ptr(&mut self) -> *mut u8 {
        let ptr = unsafe { Buffer_pointer_mut(self.buffer_mut().0.as_mut_ptr()) };
        unsafe { ptr.add(self.end()) }
    }

    fn unfilled(&mut self) -> &mut [u8] {
        let ptr = self.unfilled_ptr();
        unsafe { slice::from_raw_parts_mut(ptr, self.unfilled_len()) }
    }
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn len(&self) -> usize {
        unsafe { Buffer_len(self.buffer().0.as_ptr()) }
    }
    fn add_len(&mut self, len: usize) {
        unsafe { Buffer_add_len(self.buffer_mut().0.as_mut_ptr(), len) }
    }
    fn offset(&self) -> Range<usize> {
        self.start()..self.end()
    }
}


pub trait ReadExt<'a> {
    fn size(&self) -> usize;
    fn position(&self) -> usize;
    fn set_position(&mut self, pos: usize);
    fn add_len(&mut self, len: usize);
    fn unread_ptr(&self) -> *const u8;
    fn check(&self, need: usize) -> Result<usize, BufferError> {
        let pos = self.position();
        let len = self.size();
        if pos + need > len { return Err(BufferError::IndexOutBound { size: len, index: pos + need }); }
        Ok(pos)
    }

    #[inline]
    fn current(&self) -> u8 {
        self.check(1).unwrap();
        let ptr = self.unread_ptr();
        unsafe { ptr.read_unaligned() }.to_be()
    }
    fn read_u8(&mut self) -> Result<u8, BufferError> {
        self.check(1)?;
        let ptr = self.unread_ptr();
        let res = unsafe { ptr.read_unaligned() }.to_be();
        self.add_len(1);
        Ok(res)
    }

    fn read_u16(&mut self) -> Result<u16, BufferError> {
        self.check(2)?;
        let ptr = self.unread_ptr() as *const u16;
        let res = unsafe { ptr.read_unaligned() }.to_be();
        self.add_len(2);
        Ok(res)
    }

    fn read_u32(&mut self) -> Result<u32, BufferError> {
        self.check(4)?;
        let ptr = self.unread_ptr() as *const u32;
        let res = unsafe { ptr.read_unaligned() }.to_be();
        self.add_len(4);
        Ok(res)
    }

    fn read_u64(&mut self) -> Result<u64, BufferError> {
        self.check(8)?;
        let ptr = self.unread_ptr() as *const u64;
        let res = unsafe { ptr.read_unaligned() }.to_be();
        self.add_len(8);
        Ok(res)
    }

    fn read_u24(&mut self) -> Result<u24, BufferError> {
        self.check(3)?;
        let ptr = self.unread_ptr() as *const u24;
        let res = unsafe { ptr.read_unaligned() << 8 }.to_be();
        self.add_len(3);
        Ok(res)
    }


    fn read_slice(&mut self, len: usize) -> Result<&'a [u8], BufferError> {
        self.check(len)?;
        let ptr = self.unread_ptr();
        self.add_len(len);
        Ok(unsafe { slice::from_raw_parts(ptr, len) })
    }

    fn read_str<E>(&mut self, len: usize) -> Result<&'a str, E>
    where
        E: From<BufferError> + From<Utf8Error>,
    {
        let slice = self.read_slice(len)?;
        Ok(std::str::from_utf8(slice)?)
    }

    fn read_reader(&mut self, len: usize) -> Result<Reader<'a>, BufferError> {
        let res = self.read_slice(len)?;
        Ok(Reader::from_slice(res))
    }

    fn read_to(&mut self, end: &[u8]) -> Result<&'a [u8], BufferError> {
        let pos = self.position();
        let len = self.size();
        let ptr = self.unread_ptr();
        let filled = unsafe { slice::from_raw_parts(ptr, len - pos) };
        let pos = filled.windows(end.len()).position(|window| window == end);
        match pos {
            None => Err(BufferError::Insufficient),
            Some(pos) => {
                let res = &filled[..pos];
                self.add_len(pos);
                Ok(res)
            }
        }
    }
}