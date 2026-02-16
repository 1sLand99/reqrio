use std::ops::Range;

pub trait WriteExt {
    fn write_u8(&mut self, v: u8) { self.write_slice(&v.to_be_bytes()) }
    fn write_u16(&mut self, v: u16) { self.write_slice(&v.to_be_bytes()) }
    fn write_u32(&mut self, v: u32) { self.write_slice(&v.to_be_bytes()) }
    fn write_u64(&mut self, v: u64) { self.write_slice(&v.to_be_bytes()) }
    fn write_i8(&mut self, v: i8) { self.write_slice(&v.to_be_bytes()) }
    fn write_i16(&mut self, v: i16) { self.write_slice(&v.to_be_bytes()) }
    fn write_i32(&mut self, v: i32) { self.write_slice(&v.to_be_bytes()) }
    fn write_i64(&mut self, v: i64) { self.write_slice(&v.to_be_bytes()) }
    fn write_slice(&mut self, v: &[u8]) {
        unsafe { buffer_write(self.as_mut_ptr().add(self.len()), v.as_ptr(), v.len()) }
        self.add_len(v.len());
    }

    fn flush(&mut self, offset: usize, token: impl AsRef<[u8]>) -> usize {
        unsafe { buffer_flush(self.as_mut_ptr(), offset, self.offset().end, token.as_ref().as_ptr(), token.as_ref().len()) }
    }

    fn as_ptr(&self) -> *const u8;
    fn as_mut_ptr(&mut self) -> *mut u8;
    fn is_empty(&self) -> bool { self.len() == 0 }
    fn len(&self) -> usize { self.offset().len() }
    fn add_len(&mut self, len: usize);
    fn is_subscribed(&self) -> bool {
        unsafe { is_subscription(self.as_ptr(), self.len()) }
    }
    fn offset(&self) -> Range<usize>;
}


unsafe extern "C" {
    fn buffer_write(buf: *mut u8, ptr: *const u8, len: usize);
    fn buffer_flush(buf: *mut u8, start: usize, end: usize, token: *const u8, tl: usize) -> usize;
    fn is_subscription(buf: *const u8, len: usize) -> bool;
}