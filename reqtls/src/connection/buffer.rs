use std::ops::Range;
use crate::{Buf, Buffer, BufferError, Reader, WriteExt};

#[derive(Default)]
pub struct QUICBuffer {
    buffer: Buffer,
    current: Range<usize>,
    remains: Vec<Range<usize>>,
}

impl QUICBuffer {
    pub fn with_capacity(capacity: usize) -> QUICBuffer {
        QUICBuffer {
            buffer: Buffer::with_capacity(capacity),
            current: 0..0,
            remains: vec![],
        }
    }

    pub fn write_at(&mut self, offset: usize, buf: Buf<'_>) -> Result<(), BufferError> {
        if offset == 0 && self.remains.is_empty() {
            assert_eq!(self.buffer.len(), 0);
            self.reset();
        }
        self.buffer.write_slice_in(offset, buf.as_ref())?;
        self.buffer.add_len(buf.len());
        let range = offset..offset + buf.len();
        if self.current.end == range.start {
            self.current.end += buf.len();
        } else if self.current.start == range.end {
            self.current.start -= buf.len();
        } else {
            self.remains.push(range);
        }
        Ok(())
    }

    pub fn flush(&mut self) -> Option<Reader<'_>> {
        while let Some(pos) = self.remains.iter().position(|r| r.start == self.current.end) {
            let range = self.remains.remove(pos);
            self.current.end += range.len();
        }
        while let Some(pos) = self.remains.iter().position(|r| r.end == self.current.start) {
            let range = self.remains.remove(pos);
            self.current.start -= range.len();
        }
        println!("flush: {:?} {:?}", self.current, self.remains);
        if self.current.start != self.current.end && self.remains.is_empty() {
            Some(Reader::from_slice(self.buffer.filled()))
        } else { None }
    }

    pub fn raw_buffer_mut(&mut self) -> &mut Buffer {
        assert_eq!(self.current, self.buffer.offset());
        &mut self.buffer
    }

    pub fn reset(&mut self) {
        self.current = 0..0;
        self.remains.clear();
        self.buffer.reset();
    }

    pub fn use_empty(&mut self, size: usize) -> bool {
        self.current.start += size;
        let empty = self.buffer.used_empty(size);
        if self.buffer.is_empty() && self.current.is_empty() {
            self.reset();
        }
        empty
    }
}