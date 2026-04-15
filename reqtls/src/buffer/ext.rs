use crate::error::RlsResult;
use crate::{BufferError, Reader};
use std::ffi::CString;
use std::ops::Range;
use std::os::raw::c_char;
use std::str::Utf8Error;

pub trait WriteExt {
    fn write_u8(&mut self, v: u8) -> Result<(), BufferError> { self.write_slice(&v.to_be_bytes()) }
    fn write_u16(&mut self, v: u16) -> Result<(), BufferError> { self.write_slice(&v.to_be_bytes()) }
    fn write_u32(&mut self, v: u32, fix: bool) -> Result<(), BufferError> {
        let r = if fix { 1..4 } else { 0..4 };
        self.write_slice(&v.to_be_bytes()[r])
    }
    fn write_ru32(&mut self, v: &u32, fix: bool) -> Result<(), BufferError> {
        let r = if fix { 1..4 } else { 0..4 };
        self.write_slice(&v.to_be_bytes()[r])
    }
    fn write_u32_in(&mut self, place: usize, v: u32, fix: bool) -> Result<usize, BufferError> {
        let r = if fix { 1..4 } else { 0..4 };
        self.write_slice_in(place, &v.to_be_bytes()[r])
    }
    fn write_u64(&mut self, v: u64) -> Result<(), BufferError> { self.write_slice(&v.to_be_bytes()) }
    fn write_i8(&mut self, v: i8) -> Result<(), BufferError> { self.write_slice(&v.to_be_bytes()) }
    fn write_i16(&mut self, v: i16) -> Result<(), BufferError> { self.write_slice(&v.to_be_bytes()) }
    fn write_i32(&mut self, v: i32) -> Result<(), BufferError> { self.write_slice(&v.to_be_bytes()) }
    fn write_i64(&mut self, v: i64) -> Result<(), BufferError> { self.write_slice(&v.to_be_bytes()) }
    fn write_slice(&mut self, v: &[u8]) -> Result<(), BufferError> {
        if self.offset().end + v.len() > self.capacity() {
            return Err(BufferError::Overflow {
                capacity: self.capacity(),
                need: self.offset().end + v.len(),
            });
        }
        let len = unsafe { buffer_write(self.as_mut_ptr().add(self.len()), v.as_ptr(), v.len()) };
        self.add_len(len);
        Ok(())
    }

    ///不更新长度，需要更新使用write_slice
    fn write_slice_in(&mut self, place: usize, v: &[u8]) -> Result<usize, BufferError> {
        if place + v.len() > self.capacity() {
            return Err(BufferError::Overflow {
                capacity: self.capacity(),
                need: place + v.len(),
            });
        }
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
    fn buffer_write(buf: *mut u8, ptr: *const u8, len: usize) -> usize;
    fn buffer_flush(buf: *mut u8, len: usize, sni: *const c_char, sl: usize, h2: bool) -> usize;
    pub fn is_subscription(token: *const c_char) -> bool;
}


pub trait ReadExt<'a> {
    fn position(&self) -> usize;
    fn set_position(&mut self, pos: usize);
    fn as_slice(&self) -> &'a [u8];
    fn add_len(&mut self, len: usize) {
        self.set_position(self.position() + len);
    }
    #[inline]
    fn current(&self) -> u8 {
        let buf = self.as_slice();
        buf[self.position()]
    }
    fn read_u8(&mut self) -> Result<u8, BufferError> {
        let pos = self.position();
        let buf = self.as_slice();
        if pos == buf.len() { return Err(BufferError::Insufficient); }
        let res = buf[pos];
        self.set_position(pos + 1);
        Ok(res)
    }

    fn read_u16(&mut self) -> Result<u16, BufferError> {
        let pos = self.position();
        let buf = self.as_slice();
        if pos + 2 > buf.len() { return Err(BufferError::Insufficient); }
        let ptr = unsafe { buf.as_ptr().add(pos) } as *const u16;
        let res = unsafe { ptr.read_unaligned() }.to_be();
        self.set_position(pos + 2);
        Ok(res)
    }

    fn read_u32(&mut self) -> Result<u32, BufferError> {
        let pos = self.position();
        let buf = self.as_slice();
        if pos + 4 > buf.len() { return Err(BufferError::Insufficient); }
        let ptr = unsafe { buf.as_ptr().add(pos) } as *const u32;
        let res = unsafe { ptr.read_unaligned() }.to_be();
        self.set_position(pos + 4);
        Ok(res)
    }

    fn read_u32_24(&mut self) -> Result<u32, BufferError> {
        let pos = self.position();
        let buf = self.as_slice();
        if pos + 3 > buf.len() { return Err(BufferError::Insufficient); }
        let ptr = unsafe { buf.as_ptr().add(pos) } as *const u32;
        let res = unsafe { ptr.read_unaligned() << 8 }.to_be();
        self.set_position(pos + 3);
        Ok(res)
    }

    fn read_u64(&mut self) -> Result<u64, BufferError> {
        let pos = self.position();
        let buf = self.as_slice();
        if pos + 8 > buf.len() { return Err(BufferError::Insufficient); }
        let ptr = unsafe { buf.as_ptr().add(pos) } as *const u64;
        let res = unsafe { ptr.read_unaligned() }.to_be();
        self.set_position(pos + 8);
        Ok(res)
    }

    fn read_u128(&mut self) -> Result<u128, BufferError> {
        let pos = self.position();
        let buf = self.as_slice();
        if pos + 16 > buf.len() { return Err(BufferError::Insufficient); }
        let ptr = unsafe { buf.as_ptr().add(pos) } as *const u128;
        let res = unsafe { ptr.read_unaligned() }.to_be();
        self.set_position(pos + 16);
        Ok(res)
    }

    fn read_i8(&mut self) -> Result<i8, BufferError> {
        let pos = self.position();
        let buf = self.as_slice();
        if pos == buf.len() { return Err(BufferError::Insufficient); }
        let res = buf[pos] as i8;
        self.set_position(pos + 1);
        Ok(res)
    }

    fn read_i16(&mut self) -> Result<i16, BufferError> {
        let pos = self.position();
        let buf = self.as_slice();
        if pos + 2 > buf.len() { return Err(BufferError::Insufficient); }
        let ptr = unsafe { buf.as_ptr().add(pos) } as *const i16;
        let res = unsafe { ptr.read_unaligned() }.to_be();
        self.set_position(pos + 2);
        Ok(res)
    }

    fn read_i32(&mut self) -> Result<i32, BufferError> {
        let pos = self.position();
        let buf = self.as_slice();
        if pos + 4 > buf.len() { return Err(BufferError::Insufficient); }
        let ptr = unsafe { buf.as_ptr().add(pos) } as *const i32;
        let res = unsafe { ptr.read_unaligned() }.to_be();
        self.set_position(pos + 4);
        Ok(res)
    }

    fn read_i64(&mut self) -> Result<i64, BufferError> {
        let pos = self.position();
        let buf = self.as_slice();
        if pos + 8 > buf.len() { return Err(BufferError::Insufficient); }
        let ptr = unsafe { buf.as_ptr().add(pos) } as *const i64;
        let res = unsafe { ptr.read_unaligned() }.to_be();
        self.set_position(pos + 8);
        Ok(res)
    }

    fn read_i128(&mut self) -> Result<i128, BufferError> {
        let pos = self.position();
        let buf = self.as_slice();
        if pos + 16 > buf.len() { return Err(BufferError::Insufficient); }
        let ptr = unsafe { buf.as_ptr().add(pos) } as *const i128;
        let res = unsafe { ptr.read_unaligned() }.to_be();
        self.set_position(pos + 16);
        Ok(res)
    }

    fn read_slice(&mut self, len: usize) -> Result<&'a [u8], BufferError> {
        let pos = self.position();
        let buf = self.as_slice();
        if pos + len > buf.len() { return Err(BufferError::Insufficient); }
        self.set_position(pos + len);
        Ok(&self.as_slice()[pos..pos + len])
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