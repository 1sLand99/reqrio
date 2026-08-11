use crate::error::HlsResult;
use crate::pack::{HPackDecode, HPackEncode};
use crate::packet::HeaderParam;
use crate::reader::ReadExt;
use crate::request::RequestBuffer;
use crate::{Body, Fingerprint, FrameFlag, FrameType, H2Frame, H2Setting, Header, Response};
#[cfg(feature = "log")]
use crate::{warn, debug};
use reqtls::{u24, Buffer, Reader, WriteExt};
use std::collections::HashMap;
use crate::stream::Stream;

pub struct HTTP2StreamS {
    encoder: HPackEncode,
    decoder: HPackDecode,
    sid: u32,
    stream: Stream,
    read_buffer: Buffer,
    write_buffer: Buffer,
    increment: u32,
}


impl HTTP2StreamS {
    pub fn new(mut stream: Stream, fingerprint: &Fingerprint) -> HlsResult<HTTP2StreamS> {
        let mut buffer = Buffer::with_capacity(24657);
        buffer.write_slice(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")?;
        fingerprint.h2().build_setting().write_to(&mut buffer)?;
        fingerprint.h2().build_window_update().write_to(&mut buffer)?;
        stream.sync_write(buffer.filled())?;
        buffer.reset();
        Ok(HTTP2StreamS {
            encoder: HPackEncode::new(65536),
            decoder: HPackDecode::new(65536),
            sid: 1,
            stream,
            read_buffer: buffer,
            write_buffer: Buffer::with_capacity(16438),
            increment: 0,
        })
    }

    fn send_inner<'a>(&'a mut self, header: &Header, body: &Body<'_>, mut param: HeaderParam<'a>) -> HlsResult<u64> {
        param.hpack_encoder = Some(&mut self.encoder);
        param.h_sid = &self.sid;
        let mut request = RequestBuffer::new(header, body, param)?;
        loop {
            self.write_buffer.reset();
            let len = request.read(&mut self.write_buffer)?;
            if len == 0 { break; }
            self.stream.sync_write(self.write_buffer.filled())?;
        }
        self.write_buffer.reset();
        Ok(self.sid as u64)
    }

    pub fn send(&mut self, header: &Header, body: &Body<'_>, param: HeaderParam<'_>) -> HlsResult<u64> {
        let sid = self.send_inner(header, body, param)?;
        self.sid += 2;
        Ok(sid)
    }

    fn read_size(&mut self, max_size: usize) -> HlsResult<()> {
        while self.read_buffer.len() < max_size {
            self.read_buffer.check_move(16438)?;
            self.stream.sync_read(&mut self.read_buffer)?;
        }
        Ok(())
    }

    fn read_next_frame(&mut self) -> HlsResult<usize> {
        if self.read_buffer.len() < 5 { self.read_size(5)? };
        let filled = self.read_buffer.filled();
        let mut frame_len = u24::from_be_bytes([0, filled[0], filled[1], filled[2]]) as usize + 9;
        let priority = filled[4] & 0b0010_0000 == 0b0010_0000;
        if priority { frame_len += 5; }
        self.read_size(frame_len)?;
        Ok(frame_len)
    }

    pub fn recv(&mut self, responses: &mut HashMap<u64, Response>) -> HlsResult<Vec<u64>> {
        let frame_size = self.read_next_frame()?;
        let res = self.handle_frame(frame_size, responses);
        if !self.write_buffer.is_empty() { self.stream.sync_write(self.write_buffer.filled())?; }
        if self.read_buffer.used_empty(frame_size) { self.read_buffer.reset(); };
        res
    }

    pub fn stream(&self) -> &Stream {
        &self.stream
    }
}

impl H2Handle for HTTP2StreamS {
    fn params(&mut self) -> H2Param<'_> {
        H2Param {
            read_buffer: &self.read_buffer,
            write_buffer: &mut self.write_buffer,
            encoder: &mut self.encoder,
            decoder: &mut self.decoder,
            increment: &mut self.increment,
        }
    }
}

struct H2Param<'a> {
    read_buffer: &'a Buffer,
    write_buffer: &'a mut Buffer,
    encoder: &'a mut HPackEncode,
    decoder: &'a mut HPackDecode,
    increment: &'a mut u32,
}

trait H2Handle {
    fn params(&mut self) -> H2Param<'_>;
    fn handle_frame(&mut self, frame_size: usize, responses: &mut HashMap<u64, Response>) -> HlsResult<Vec<u64>> {
        let param = self.params();
        let reader = Reader::from_slice(&param.read_buffer.filled()[..frame_size]);
        let frame = H2Frame::from_reader(reader)?;
        let sid = frame.stream_identifier() as u64;
        let mut res = vec![];
        #[cfg(feature = "log")]
        debug!("{}-{:?}-{:?}-{:?}", sid, frame.frame_type(), frame.flag().end_stream(), responses.keys());
        match frame.frame_type() {
            FrameType::Data => {
                let resp = responses.get_mut(&sid).ok_or("resp not inited")?;
                resp.push_raw_slice(frame.payload())?;
                if frame.flag().end_stream() { res.push(sid); }
            }
            FrameType::Headers => {
                let resp = responses.get_mut(&sid).ok_or("resp not inited")?;
                param.decoder.decode_into(frame.payload(), resp.header_mut())?;
                if frame.flag().end_header() { resp.make_coding()?; }
                if frame.flag().end_stream() { res.push(sid); }
            }
            FrameType::RstStream | FrameType::Goaway => return Err((*frame.frame_type()).into()),
            FrameType::Settings => {
                let mut reader = Reader::from_slice(frame.payload());
                while let Ok(setting) = H2Setting::from_reader(&mut reader) {
                    if let H2Setting::HeaderTableSize(size) = setting {
                        param.encoder.update_table_size(size as usize);
                        param.decoder.update_table_size(size as usize);
                    }
                }
                if frame.frame_type() == &FrameType::Settings && frame.flag().end_stream() {
                    let mut ack_frame = H2Frame::none_frame();
                    ack_frame.set_frame_type(FrameType::Settings);
                    ack_frame.set_flag(FrameFlag::EndStream);
                    param.write_buffer.write_slice(&ack_frame.to_bytes())?;
                }
            }
            FrameType::WindowUpdate => *param.increment = u32::from_be_bytes(frame.payload().try_into()?),
            _ => {
                #[cfg(feature = "log")]
                warn!("ignore h2 frame-{:?}",frame.frame_type());
            }
        }
        Ok(res)
    }
}


#[cfg(feature = "aync")]
pub struct HTTP2StreamA {
    encoder: HPackEncode,
    decoder: HPackDecode,
    sid: u32,
    stream: Stream,
    read_buffer: Buffer,
    write_buffer: Buffer,
    increment: u32,
}


#[cfg(feature = "aync")]
impl HTTP2StreamA {
    pub async fn new(mut stream: Stream, fingerprint: &Fingerprint) -> HlsResult<HTTP2StreamA> {
        let mut buffer = Buffer::with_capacity(24657);
        buffer.write_slice(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")?;
        fingerprint.h2().build_setting().write_to(&mut buffer)?;
        fingerprint.h2().build_window_update().write_to(&mut buffer)?;
        stream.async_write(buffer.filled()).await?;
        buffer.reset();
        Ok(HTTP2StreamA {
            encoder: HPackEncode::new(65536),
            decoder: HPackDecode::new(65536),
            sid: 1,
            stream,
            read_buffer: buffer,
            write_buffer: Buffer::with_capacity(16438),
            increment: 0,
        })
    }

    pub async fn send_inner(&mut self, header: &Header, body: &Body<'_>, mut param: HeaderParam<'_>) -> HlsResult<u64> {
        param.hpack_encoder = Some(&mut self.encoder);
        param.h_sid = &self.sid;
        let mut request = RequestBuffer::new(header, body, param)?;
        loop {
            self.write_buffer.reset();
            let len = request.read(&mut self.write_buffer)?;
            if len == 0 { break; }
            self.stream.async_write(self.write_buffer.filled()).await?;
        }
        self.write_buffer.reset();
        Ok(self.sid as u64)
    }

    pub async fn send(&mut self, header: &Header, body: &Body<'_>, param: HeaderParam<'_>) -> HlsResult<u64> {
        let sid = self.send_inner(header, body, param).await?;
        self.sid += 2;
        Ok(sid)
    }

    async fn read_size(&mut self, max_size: usize) -> HlsResult<()> {
        while self.read_buffer.len() < max_size {
            self.read_buffer.check_move(16438)?;
            self.stream.async_read(&mut self.read_buffer).await?;
        }
        Ok(())
    }

    async fn read_next_frame(&mut self) -> HlsResult<usize> {
        if self.read_buffer.len() < 5 { self.read_size(5).await? };
        let filled = self.read_buffer.filled();
        let mut frame_len = u24::from_be_bytes([0, filled[0], filled[1], filled[2]]) as usize + 9;
        let priority = filled[4] & 0b0010_0000 == 0b0010_0000;
        if priority { frame_len += 5; }
        self.read_size(frame_len).await?;
        Ok(frame_len)
    }

    pub async fn recv(&mut self, responses: &mut HashMap<u64, Response>) -> HlsResult<Vec<u64>> {
        let frame_size = self.read_next_frame().await?;
        let res = self.handle_frame(frame_size, responses);
        if !self.write_buffer.is_empty() { self.stream.async_write(self.write_buffer.filled()).await?; }
        if self.read_buffer.used_empty(frame_size) { self.read_buffer.reset(); };
        res
    }

    pub fn stream(&self) -> &Stream {
        &self.stream
    }
}

#[cfg(feature = "aync")]
impl H2Handle for HTTP2StreamA {
    fn params(&mut self) -> H2Param<'_> {
        H2Param {
            increment: &mut self.increment,
            read_buffer: &self.read_buffer,
            write_buffer: &mut self.write_buffer,
            encoder: &mut self.encoder,
            decoder: &mut self.decoder,
        }
    }
}