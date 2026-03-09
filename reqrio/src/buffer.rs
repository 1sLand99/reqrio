use crate::error::{HlsError, HlsResult};
use reqtls::WriteExt;
use std::io::Read;
use std::ops::{Index, IndexMut, Range, RangeFrom, RangeFull, RangeTo};
use std::ptr;
#[cfg(feature = "tokio")]
use tokio::io::AsyncReadExt;

pub struct Buffer {
    buffer: Vec<u8>,
    offset: Range<usize>,
}

impl Default for Buffer {
    fn default() -> Self {
        Buffer::with_capacity(16 * 1024)
    }
}

impl Buffer {
    pub fn with_capacity(capacity: usize) -> Buffer {
        let buffer = vec![0u8; capacity];
        Buffer { buffer, offset: 0..0 }
    }

    pub fn new_bytes(bytes: Vec<u8>) -> Self {
        Buffer {
            offset: 0..bytes.len(),
            buffer: bytes,
        }
    }

    #[cfg(feature = "tokio")]
    pub async fn async_read<S: AsyncReadExt + Unpin>(&mut self, stream: &mut S) -> HlsResult<()> {
        self.async_read_limit(stream, self.buffer.capacity() - self.offset.end).await
    }

    #[cfg(feature = "tokio")]
    pub async fn async_read_limit<S: AsyncReadExt + Unpin>(&mut self, stream: &mut S, limit: usize) -> HlsResult<()> {
        let len = stream.read(&mut self.buffer[self.offset.end..self.offset.end + limit]).await?;
        if len == 0 { return Err(HlsError::PeerClosedConnection); }
        self.offset.end += len;
        Ok(())
    }

    pub fn sync_read<S: Read>(&mut self, stream: &mut S) -> HlsResult<()> {
        self.sync_read_limit(stream, self.buffer.capacity() - self.offset.end)
    }

    pub fn sync_read_limit<S: Read>(&mut self, stream: &mut S, limit: usize) -> HlsResult<()> {
        let len = stream.read(&mut self.buffer[self.offset.end..self.offset.end + limit])?;
        if len == 0 { return Err(HlsError::PeerClosedConnection); }
        self.offset.end += len;
        Ok(())
    }

    pub fn reset(&mut self) {
        self.offset = 0..0;
    }

    pub fn is_empty(&self) -> bool {
        self.offset.is_empty()
    }

    ///使用used字节后是否为空
    pub fn used_empty(&mut self, used: usize) -> bool {
        self.offset.start += used;
        self.is_empty()
    }

    pub fn len_ptr(&mut self) -> *mut usize {
        &mut self.offset.end
    }

    pub fn set_len(&mut self, len: usize) {
        self.offset.end = self.offset.start + len;
    }

    pub fn add_len(&mut self, len: usize) {
        self.offset.end += len;
    }

    pub fn starts_with(&self, bs: &[u8]) -> bool {
        self.buffer.starts_with(bs)
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.buffer[self.offset.clone()].to_vec()
    }

    pub fn capacity(&self) -> usize {
        self.buffer.capacity()
    }

    ///必须手动管理len, 返回已push的长度
    #[must_use]
    pub fn push_slice_in(&mut self, place: usize, slice: &[u8]) -> usize {
        unsafe {
            let dst = self.buffer.as_mut_ptr().add(place);
            ptr::copy_nonoverlapping(slice.as_ref().as_ptr(), dst, slice.len());
        }
        slice.len()
    }

    pub fn filled(&self) -> &[u8] {
        &self.buffer[self.offset.clone()]
    }

    pub fn filled_mut(&mut self) -> &mut [u8] {
        &mut self.buffer[self.offset.clone()]
    }

    pub fn unfilled_mut(&mut self) -> &mut [u8] {
        &mut self.buffer[self.offset.end..]
    }

    pub fn copy_within(&mut self, r: Range<usize>, pos: usize) {
        self.buffer.copy_within(r, pos);
    }

    pub fn move_to(&mut self, r: Range<usize>, pos: usize) {
        self.offset = pos..pos;
        self.offset.end += r.len();
        self.copy_within(r, pos);
    }

    pub fn drain(&mut self, range: RangeTo<usize>) -> Vec<u8> {
        let res = self.buffer[range].to_vec();
        self.copy_within(range.end..self.offset.end, 0);
        self.offset.end -= range.end;
        res
    }
}

impl Index<RangeTo<usize>> for Buffer {
    type Output = [u8];
    fn index(&self, i: RangeTo<usize>) -> &[u8] {
        &self.buffer[..i.end]
    }
}

impl Index<RangeFrom<usize>> for Buffer {
    type Output = [u8];
    fn index(&self, i: RangeFrom<usize>) -> &[u8] {
        &self.buffer[i.start..self.offset.len()]
    }
}

impl Index<Range<usize>> for Buffer {
    type Output = [u8];
    fn index(&self, i: Range<usize>) -> &[u8] {
        &self.buffer[i]
    }
}

impl IndexMut<RangeTo<usize>> for Buffer {
    fn index_mut(&mut self, i: RangeTo<usize>) -> &mut [u8] {
        &mut self.buffer[i]
    }
}

impl IndexMut<RangeFrom<usize>> for Buffer {
    fn index_mut(&mut self, i: RangeFrom<usize>) -> &mut [u8] {
        &mut self.buffer[i]
    }
}

impl IndexMut<Range<usize>> for Buffer {
    fn index_mut(&mut self, i: Range<usize>) -> &mut [u8] {
        &mut self.buffer[i]
    }
}

impl Index<usize> for Buffer {
    type Output = u8;
    fn index(&self, i: usize) -> &u8 {
        &self.buffer[i]
    }
}

impl Index<RangeFull> for Buffer {
    type Output = [u8];
    fn index(&self, i: RangeFull) -> &[u8] {
        &self.buffer[i]
    }
}

impl IndexMut<RangeFull> for Buffer {
    fn index_mut(&mut self, i: RangeFull) -> &mut [u8] {
        &mut self.buffer[i]
    }
}

impl WriteExt for Buffer {
    fn as_ptr(&self) -> *const u8 {
        self.buffer.as_ptr()
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.buffer.as_mut_ptr()
    }

    fn add_len(&mut self, len: usize) {
        self.offset.end += len;
    }

    fn offset(&self) -> Range<usize> {
        self.offset.start..self.offset.end
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        self.buffer.clear();
        self.buffer.shrink_to_fit();
    }
}