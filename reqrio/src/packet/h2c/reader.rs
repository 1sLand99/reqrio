use crate::body::H1BodyReader;
use crate::error::HlsResult;
use crate::reader::{ReadExt, Reader};
use crate::{Buffer, FrameFlag, FrameType};
use reqtls::{RlsError, WriteExt};

pub struct H2FrameRBuf<'a> {
    pd_len: usize,
    frame_type: FrameType,
    frame_flag: FrameFlag,
    payload: &'a [u8],
}


impl<'a> H2FrameRBuf<'a> {
    pub fn from_bytes(bytes: &'a [u8], frame_type: FrameType) -> HlsResult<H2FrameRBuf<'a>> {
        if bytes.len() < 5 { return Err(RlsError::MessageTooShort.into()); }
        let pd_len = u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]) as usize;
        let frame_flag = FrameFlag::from_u8(bytes[4]);
        let (frame_len, _) = match frame_flag.priority() {
            true => (pd_len + 14, &bytes[9..14]),
            false => (pd_len + 9, &bytes[0..0])
        };
        if bytes.len() < frame_len { return Err(RlsError::MessageTooShort.into()); }
        let payload = if frame_flag.priority() { &bytes[14..frame_len] } else { &bytes[9..frame_len] };
        Ok(H2FrameRBuf {
            pd_len,
            frame_type,
            frame_flag,
            payload,
        })
    }

    pub fn buffer_enough(buffer: &Buffer) -> HlsResult<(FrameType, FrameFlag, usize)> {
        let filled = buffer.filled();
        if filled.len() < 5 { return Err(RlsError::MessageTooShort.into()); }
        let pd_len = u32::from_be_bytes([0, filled[0], filled[1], filled[2]]) as usize;
        let frame_flag = FrameFlag::from_u8(filled[4]);
        let frame_len = if frame_flag.priority() { pd_len + 14 } else { pd_len + 9 };
        if filled.len() < frame_len { return Err(RlsError::MessageTooShort.into()); }
        let frame_type = FrameType::from_u8(filled[3])?;
        Ok((frame_type, frame_flag, frame_len))
    }

    pub fn frame_len(&self) -> usize {
        if self.frame_flag.priority() { self.pd_len + 14 } else { self.pd_len + 9 }
    }

    pub fn is_end_frame(&self) -> bool {
        self.frame_flag.end_stream() &&
            (self.frame_type == FrameType::Data || self.frame_type == FrameType::Headers)
    }

    pub fn frame_type(&self) -> &FrameType {
        &self.frame_type
    }

    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }

    pub fn frame_flag(&self) -> &FrameFlag {
        &self.frame_flag
    }
}

pub struct H2FrameHead<'a> {
    pd_len: u32,
    frame_type: FrameType,
    frame_flag: FrameFlag,
    stream_identifier: &'a u32,
    weight: u8,
    wrote: bool,
}

impl<'a> H2FrameHead<'a> {
    pub fn new(sid: &'a u32, pd_len: usize, end_stream: bool) -> H2FrameHead<'a> {
        let mut frame_flag = FrameFlag::from_u8(0);
        if end_stream {
            frame_flag |= FrameFlag::EndStream;
        }
        H2FrameHead {
            pd_len: pd_len as u32,
            frame_type: FrameType::Data,
            frame_flag,
            stream_identifier: sid,
            weight: 0,
            wrote: false,
        }
    }
}

impl<'a> ReadExt for H2FrameHead<'a> {
    fn wrote(&self) -> bool {
        self.wrote
    }

    fn read(&mut self, buf: &mut Reader) -> HlsResult<usize> {
        let start = buf.offset().end;
        if buf.unfilled_len() < 14 { return Ok(buf.offset().end - start); }
        buf.write_u32(self.pd_len, true);
        buf.write_u8(self.frame_type as u8);
        buf.write_u8(self.frame_flag.as_u8());
        buf.write_ru32(self.stream_identifier, false);
        if self.frame_flag.priority() {
            buf.write_u8(self.weight);
            buf.write_slice(&[128, 0, 0, 0]);
        }
        self.wrote = true;
        Ok(buf.offset().end - start)
    }
}


///`H2FrameBufs`主要是构建H2 Body Frame；因为Header Frame需要经过hpack编码长度不可知，无法适用
pub struct H2BodyReader<'a> {
    frames: Vec<H2FrameHead<'a>>,
    body: H1BodyReader<'a>,
    frame_wrote: usize,
    pos: usize,
    wrote: bool,
}

impl<'a> H2BodyReader<'a> {
    pub fn new_size(buffer_size: usize, body: H1BodyReader<'a>, sid: &'a u32) -> H2BodyReader<'a> {
        let body_len = body.len();
        let chunks = (0..body_len).step_by(buffer_size).map(|i| (body_len - i).min(buffer_size));
        let chunk_len = chunks.len();
        H2BodyReader {
            frames: chunks.into_iter().enumerate().map(|(i, size)| H2FrameHead::new(sid, size, i == chunk_len - 1)).collect(),
            body,
            frame_wrote: 0,
            pos: 0,
            wrote: false,
        }
    }
}

impl<'a> ReadExt for H2BodyReader<'a> {
    fn wrote(&self) -> bool {
        self.wrote
    }

    fn read(&mut self, buf: &mut Reader) -> HlsResult<usize> {
        let start = buf.offset().end;
        for (index, frame) in self.frames.iter_mut().enumerate() {
            if index < self.pos { continue; }
            if !frame.wrote {
                let len = frame.read(buf)?;
                if len == 0 { return Ok(buf.offset().end - start); }
                if frame.wrote { self.frame_wrote = 0; }
            }
            if buf.unfilled_len() < frame.pd_len as usize { return Ok(buf.offset().end - start); }
            let want = frame.pd_len as usize - self.frame_wrote;
            let end = if buf.unfilled().len() < want { buf.unfilled_len() } else { want };
            let mut render = Reader::new(&mut buf.unfilled()[..end]);
            let len = self.body.read(&mut render)?;
            buf.add_len(len);
            assert_eq!(len, want);
            self.pos += 1;
        }
        self.wrote = true;
        Ok(buf.offset().end - start)
    }
}