use crate::error::RlsResult;
use crate::{BufferError, Reader};
use std::ffi::CString;
use std::ops::Range;
use std::os::raw::c_char;
use std::slice;
use std::str::Utf8Error;
#[cfg(feature = "log")]
use log::warn;

#[allow(non_camel_case_types)]
pub type u24 = u32;

pub trait WriteExt {
    fn check(&self, len: usize, need: usize) -> Result<usize, BufferError> {
        let capacity = self.capacity();
        if len + need > capacity {
            Err(BufferError::Overflow {
                capacity,
                len,
                need,
            })
        } else { Ok(len) }
    }
    fn write_u8(&mut self, v: u8) -> Result<(), BufferError> {
        let place = self.check(self.len(), 1)?;
        let len = unsafe { write_u8(self.as_mut_ptr().add(place), &v) };
        self.add_len(len);
        Ok(())
    }
    fn write_u16_be(&mut self, v: u16) -> Result<(), BufferError> {
        let place = self.check(self.len(), 2)?;
        let len = unsafe { write_u16(self.as_mut_ptr().add(place), &v) };
        self.add_len(len);
        Ok(())
    }

    #[inline]
    fn write_u16(&mut self, v: u16) -> Result<(), BufferError> {
        self.write_u16_be(v.to_be())
    }

    fn write_u24_be(&mut self, v: u24) -> Result<(), BufferError> {
        let place = self.check(self.len(), 3)?;
        let len = unsafe { write_u32(self.as_mut_ptr().add(place), &v, true) };
        self.add_len(len);
        Ok(())
    }

    #[inline]
    fn write_u24(&mut self, v: u24) -> Result<(), BufferError> {
        self.write_u24_be(v.to_be())
    }

    fn write_u24_in(&mut self, place: usize, v: u24) -> Result<usize, BufferError> {
        let place = self.check(place, 3)?;
        let len = unsafe { write_u32(self.as_mut_ptr().add(place), &v.to_be(), true) };
        Ok(len)
    }

    fn write_u32_be(&mut self, v: u32) -> Result<(), BufferError> {
        let place = self.check(self.len(), 4)?;
        let len = unsafe { write_u32(self.as_mut_ptr().add(place), &v, false) };
        self.add_len(len);
        Ok(())
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
        let place = self.check(self.len(), v.len())?;
        let len = unsafe { buffer_write(self.as_mut_ptr().add(place), v.as_ptr(), v.len()) };
        self.add_len(len);
        Ok(())
    }

    ///不更新长度，需要更新使用write_slice
    fn write_slice_in(&mut self, place: usize, v: &[u8]) -> Result<usize, BufferError> {
        let place = self.check(place, v.len())?;
        let len = unsafe { buffer_write(self.as_mut_ptr().add(place), v.as_ptr(), v.len()) };
        Ok(len)
    }

    fn flush(&mut self, offset: usize, sni: String, h2: bool) -> RlsResult<usize> {
        let sl = sni.len();
        let csni = CString::new(sni)?;
        let len = unsafe { buffer_flush(self.as_mut_ptr().add(offset), self.offset().end - offset, csni.as_ptr(), sl, h2) };
        Ok(len)
    }

    fn check_subscription(&self, token: impl AsRef<str>) -> RlsResult<i32> {
        let is_subscribed = unsafe { is_subscription(CString::new(token.as_ref())?.as_ptr()) };
        if !is_subscribed {
            #[cfg(feature = "log")]
            warn!("[Fingerprint] You have not subscribed yet, so this call will be ignored.");
            #[cfg(not(feature = "log"))]
            println!("\x1b[01;33m[Fingerprint] WARN \x1b[0m You have not subscribed yet, so this call will be ignored.");
        }
        Ok(if is_subscribed { 0 } else { -2 })
    }

    fn as_ptr(&self) -> *const u8;
    fn as_mut_ptr(&mut self) -> *mut u8;
    fn is_empty(&self) -> bool { self.offset().is_empty() }
    fn len(&self) -> usize { self.offset().len() }
    fn add_len(&mut self, len: usize);
    fn offset(&self) -> Range<usize>;
    fn capacity(&self) -> usize;
}


unsafe extern "C" {
    fn write_u8(ptr: *mut u8, val: &u8) -> usize;
    fn write_u16(ptr: *mut u8, val: &u16) -> usize;
    fn write_u32(ptr: *mut u8, val: &u32, fix: bool) -> usize;
    fn buffer_write(buf: *mut u8, ptr: *const u8, len: usize) -> usize;
    fn buffer_flush(buf: *mut u8, len: usize, sni: *const c_char, sl: usize, h2: bool) -> usize;
    pub fn is_subscription(token: *const c_char) -> bool;
}

pub trait ReadExt<'a> {
    fn size(&self) -> usize;
    fn position(&self) -> usize;
    fn set_position(&mut self, pos: usize);
    fn add_len(&mut self, len: usize);
    fn check(&self, need: usize) -> Result<usize, BufferError> {
        let pos = self.position();
        let len = self.size();
        if pos + need > len { return Err(BufferError::IndexOutBound { size: len, index: pos + need }); }
        Ok(pos)
    }
    fn as_ptr(&self) -> *const u8;
    #[inline]
    fn current(&self) -> u8 {
        let pos = self.check(1).unwrap();
        unsafe { self.as_ptr().add(pos).read_unaligned() }.to_be()
    }
    fn read_u8(&mut self) -> Result<u8, BufferError> {
        let pos = self.check(1)?;
        let res = unsafe { self.as_ptr().add(pos).read_unaligned() }.to_be();
        self.add_len(1);
        Ok(res)
    }

    fn read_u16(&mut self) -> Result<u16, BufferError> {
        let pos = self.check(2)?;
        let ptr = unsafe { self.as_ptr().add(pos) } as *const u16;
        let res = unsafe { ptr.read_unaligned() }.to_be();
        self.add_len(2);
        Ok(res)
    }

    fn read_u32(&mut self) -> Result<u32, BufferError> {
        let pos = self.check(4)?;
        let ptr = unsafe { self.as_ptr().add(pos) } as *const u32;
        let res = unsafe { ptr.read_unaligned() }.to_be();
        self.add_len(4);
        Ok(res)
    }

    fn read_u24(&mut self) -> Result<u24, BufferError> {
        let pos = self.check(3)?;
        let ptr = unsafe { self.as_ptr().add(pos) } as *const u24;
        let res = unsafe { ptr.read_unaligned() << 8 }.to_be();
        self.add_len(3);
        Ok(res)
    }


    fn read_slice(&mut self, len: usize) -> Result<&'a [u8], BufferError> {
        let pos = self.check(len)?;
        self.add_len(len);
        Ok(unsafe{slice::from_raw_parts(self.as_ptr().add(pos), len) })
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
}