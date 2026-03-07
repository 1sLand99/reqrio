pub use flag::FrameFlag;
use reqtls::{RlsError, WriteExt};
pub use typo::FrameType;

use setting::Setting;
mod setting;
mod typo;
mod flag;

use crate::error::HlsResult;
use crate::Buffer;
use std::fmt::Debug;

#[derive(Debug)]
pub struct H2Frame<'a> {
    len: usize,
    frame_type: FrameType,
    flag: FrameFlag,
    stream_identifier: u32,
    stream_dependency: u32,
    weight: u8,
    payload: &'a [u8],
    settings: Vec<Setting>,
}

impl<'a> H2Frame<'a> {
    pub fn none_frame() -> H2Frame<'a> {
        H2Frame {
            len: 0,
            frame_type: FrameType::Data,
            flag: FrameFlag::default(),
            stream_identifier: 0,
            stream_dependency: 0,
            weight: 0,
            payload: &[],
            settings: vec![],
        }
    }

    pub fn from_bytes(buffer: &'a Buffer) -> HlsResult<H2Frame<'a>> {
        if buffer.len() < 9 { return Err("byte not enough".into()); }
        let len = u32::from_be_bytes([0, buffer[0], buffer[1], buffer[2]]) as usize;
        let frame_type = FrameType::from_u8(buffer[3])?;
        let flag = FrameFlag::from_u8(buffer[4]);
        let mut stream_identifier = u32::from_be_bytes(buffer[5..9].try_into()?);
        stream_identifier &= !2147483648;
        if buffer.len() < 9 + len { return Err("byte not enough".into()); }
        let (dependency, weight, payload) = if flag.priority() {
            (u32::from_be_bytes(buffer[9..13].try_into()?), buffer[13], &buffer[14..9 + len])
        } else {
            (0, 0, &buffer[9..9 + len])
        };
        let mut settings = vec![];
        if frame_type == FrameType::Settings {
            let mut cl = 0;
            while cl < payload.len() {
                let setting = Setting::from_bytes(&payload[cl..cl + 6])?;
                settings.push(setting);
                cl += 6;
            }
        }


        Ok(H2Frame {
            len,
            frame_type,
            flag,
            stream_identifier,
            stream_dependency: dependency,
            weight,
            payload,
            settings,
        })
    }

    pub fn write_to<W: WriteExt>(mut self, writer: &mut W) {
        let len = if self.flag.priority() { self.payload.len() + 5 } else { self.payload.len() } as u32;
        writer.write_u32(len, true);
        writer.write_u8(self.frame_type.to_u8());
        let priority = self.flag.priority();

        writer.write_u8(self.flag.into_inner());
        writer.write_u32(self.stream_identifier, false);
        if priority {
            self.stream_dependency |= 2147483648;
            writer.write_u32(self.stream_dependency, false);
            writer.write_u8(self.weight);
        }
        match self.frame_type {
            FrameType::Settings => for setting in self.settings {
                setting.write_to(writer);
            }
            _ => writer.write_slice(self.payload),
        }
    }

    pub fn to_bytes(mut self) -> Vec<u8> {
        let mut res = (if self.flag.priority() { self.payload.len() + 5 } else { self.payload.len() } as u32).to_be_bytes()[1..].to_vec();
        res.push(self.frame_type.to_u8());
        let mut dep_bs = vec![];
        if self.flag.priority() {
            self.stream_dependency |= 2147483648;
            dep_bs = self.stream_dependency.to_be_bytes().to_vec();

            dep_bs.push(self.weight);
        }
        res.push(self.flag.into_inner());
        let stream_identifier = self.stream_identifier;
        res.extend(stream_identifier.to_be_bytes());
        res.extend(dep_bs);
        res.extend(self.payload);
        res
    }

    pub fn window_update() -> H2Frame<'a> {
        let mut frame = H2Frame::none_frame();
        frame.len = 4;
        frame.frame_type = FrameType::WindowUpdate;
        frame.payload = &[0, 239, 0, 1];
        frame
    }

    pub fn default_setting() -> H2Frame<'a> {
        let settings = Setting::default();
        H2Frame {
            len: settings.len() * 6,
            frame_type: FrameType::Settings,
            flag: FrameFlag::default(),
            stream_identifier: 0,
            stream_dependency: 0,
            weight: 0,
            settings,
            payload: &[],
        }
    }

    pub fn new_header(hdr_bs: &'a [u8], body_len: usize, sid: u32) -> H2Frame<'a> {
        let mut res = H2Frame {
            len: hdr_bs.len(),
            frame_type: FrameType::Headers,
            flag: FrameFlag::EndHeader,
            stream_identifier: sid,
            stream_dependency: 0,
            weight: 0,
            payload: hdr_bs,
            settings: vec![],
        };
        if body_len == 0 { res.flag |= FrameFlag::EndStream; }
        res
    }

    pub fn new_body(mut body: &'a [u8], sid: u32) -> Vec<H2Frame<'a>> {
        if body.is_empty() { return vec![]; }
        let max_len = u32::from_be_bytes([0, 255, 255, 255]) as usize;
        let mut res = vec![];
        loop {
            let pos = if body.len() >= max_len { max_len } else { body.len() };
            let (payload, remain) = body.split_at(pos);
            body = remain;
            res.push(H2Frame {
                len: payload.len(),
                frame_type: FrameType::Data,
                flag: FrameFlag::default(),
                stream_identifier: sid,
                stream_dependency: 0,
                weight: 0,
                payload,
                settings: vec![],
            });
            if pos >= body.len() { break; }
        }
        if !res.is_empty() { res.last_mut().unwrap().flag |= FrameFlag::EndStream; }
        res
    }

    pub fn flag(&self) -> &FrameFlag {
        &self.flag
    }

    pub fn frame_type(&self) -> &FrameType {
        &self.frame_type
    }

    pub fn payload(&self) -> &[u8] { &self.payload }

    pub fn set_payload(&mut self, payload: &'a [u8]) { self.payload = payload }

    pub fn is_empty(&self) -> bool { self.len == 0 }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn frame_id(&self) -> u32 {
        self.stream_identifier
    }

    pub fn set_frame_type(&mut self, frame_type: FrameType) {
        self.frame_type = frame_type;
    }

    pub fn set_flag(&mut self, flag: FrameFlag) {
        self.flag = flag;
    }

    pub fn set_settings(&mut self, settings: Vec<Setting>) {
        self.settings = settings;
    }

    pub fn set_weight(&mut self, weight: u8) {
        self.weight = weight;
    }

    pub fn add_flag(&mut self, flag: FrameFlag) {
        self.flag |= flag;
    }

    pub fn set_stream_identifier(&mut self, stream_identifier: u32) {
        self.stream_identifier = stream_identifier;
    }

    pub fn stream_identifier(&self) -> u32 {
        self.stream_identifier
    }

    pub fn is_end_frame(&self) -> bool {
        self.flag.end_stream() &&
            (self.frame_type == FrameType::Data || self.frame_type == FrameType::Headers)
    }
}

#[allow(unused)]
pub struct H2FrameBuffer<'a> {
    pd_len: usize,
    frame_type: FrameType,
    frame_flag: FrameFlag,
    stream_identifier: &'a [u8],
    priority_data: &'a [u8],
    payload: &'a [u8],
}


impl<'a> H2FrameBuffer<'a> {
    pub fn from_bytes(bytes: &'a [u8], frame_type: FrameType) -> HlsResult<H2FrameBuffer<'a>> {
        if bytes.len() < 5 { return Err(RlsError::MessageTooShort.into()); }
        let pd_len = u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]) as usize;
        let frame_flag = FrameFlag::from_u8(bytes[4]);
        let (frame_len, priority_data) = match frame_flag.priority() {
            true => (pd_len + 14, &bytes[9..14]),
            false => (pd_len + 9, &bytes[0..0])
        };
        if bytes.len() < frame_len { return Err(RlsError::MessageTooShort.into()); }
        let payload = if frame_flag.priority() { &bytes[14..frame_len] } else { &bytes[9..frame_len] };
        Ok(H2FrameBuffer {
            pd_len,
            frame_type,
            frame_flag,
            stream_identifier: &bytes[5..9],
            priority_data,
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