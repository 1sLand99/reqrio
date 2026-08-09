use crate::error::HlsResult;
use crate::pack::{HPackDecode, HPackEncode};
use crate::packet::HeaderParam;
use crate::reader::ReadExt;
use crate::request::RequestBuffer;
use crate::{warn, Body, Fingerprint, FrameFlag, FrameType, H2Frame, H2Setting, Header, Response};
use reqtls::{u24, Buffer, Reader, Url, WriteExt};
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

    pub fn send(&mut self, url: &Url, header: &Header, body: &Body<'_>, fingerprint: &Fingerprint) -> HlsResult<u64> {
        let sid = self.sid;
        self.sid += 2;
        let mut request = RequestBuffer::new(header, body, HeaderParam {
            url,
            h_sid: &sid,
            hpack_encoder: Some(&mut self.encoder),
            q_sid: &0,
            qpack_encoder: None,
            body_len: 0,
            weight: &fingerprint.h2().weight,
            priority: &fingerprint.h2().priority,
        })?;
        loop {
            self.write_buffer.reset();
            let len = request.read(&mut self.write_buffer)?;
            if len == 0 { break; }
            self.stream.sync_write(self.write_buffer.filled())?;
        }
        Ok(sid as u64)
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
        loop {
            let frame_size = self.read_next_frame()?;
            let reader = Reader::from_slice(&self.read_buffer.filled()[..frame_size]);
            let frame = H2Frame::from_reader(reader)?;
            let sid = frame.stream_identifier() as u64;
            match frame.frame_type() {
                FrameType::Data => {
                    let resp = responses.get_mut(&sid).ok_or("resp not inited")?;
                    resp.push_raw_slice(frame.payload())?;
                    if frame.flag().end_stream() { return Ok(vec![sid]); }
                }
                FrameType::Headers => {
                    let resp = responses.get_mut(&sid).ok_or("resp not inited")?;
                    self.decoder.decode_into(frame.payload(), resp.header_mut())?;
                    if frame.flag().end_header() { resp.make_coding()?; }
                    if frame.flag().end_stream() { return Ok(vec![sid]); }
                }
                FrameType::RstStream | FrameType::Goaway => return Err((*frame.frame_type()).into()),
                FrameType::Settings => {
                    let mut reader = Reader::from_slice(frame.payload());
                    while let Ok(setting) = H2Setting::from_reader(&mut reader) {
                        if let H2Setting::HeaderTableSize(size) = setting {
                            self.encoder.update_table_size(size as usize);
                            self.decoder.update_table_size(size as usize);
                        }
                    }
                    if frame.frame_type() == &FrameType::Settings && frame.flag().end_stream() {
                        let mut ack_frame = H2Frame::none_frame();
                        ack_frame.set_frame_type(FrameType::Settings);
                        ack_frame.set_flag(FrameFlag::EndStream);
                        self.stream.sync_write(ack_frame.to_bytes().as_ref())?;
                    }
                }
                FrameType::WindowUpdate => self.increment = u32::from_be_bytes(frame.payload().try_into()?),
                _ => {
                    warn!("ignore h2 frame-{:?}",frame.frame_type());
                }
            }
            if self.read_buffer.used_empty(frame_size) { self.read_buffer.reset(); };
        }
    }

    pub fn stream(&self) -> &Stream {
        &self.stream
    }
}