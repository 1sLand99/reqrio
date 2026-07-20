use std::{mem, slice};
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
        let offset = self.buffer.end() + offset;
        self.buffer.write_slice_in(offset, buf.as_ref())?;
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
        if self.current.start != self.current.end && self.remains.is_empty() {
            let mut offset = mem::take(&mut self.current);
            offset.start += self.buffer.end();
            offset.end += self.buffer.end();
            let ptr = self.buffer.raw_ptr();
            let filled = unsafe { slice::from_raw_parts(ptr.add(offset.start), offset.len()) };
            Some(Reader::from_slice(filled))
        } else { None }
    }

    pub fn reset(&mut self) {
        self.current = 0..0;
        self.remains.clear();
        self.buffer.reset();
    }
}