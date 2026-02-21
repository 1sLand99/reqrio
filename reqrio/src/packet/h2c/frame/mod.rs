pub use flag::FrameFlag;
use reqtls::WriteExt;
pub use typo::FrameType;

use setting::Setting;
mod setting;
mod typo;
mod flag;

use crate::error::HlsResult;
use crate::Buffer;
use std::fmt::Debug;
use std::ptr;

#[derive(Clone, Debug)]
pub struct H2Frame {
    len: usize,
    frame_type: FrameType,
    flag: FrameFlag,
    stream_identifier: u32,
    stream_dependency: u32,
    weight: u8,
    payload: Vec<u8>,
    settings: Vec<Setting>,
}

impl H2Frame {
    pub fn none_frame() -> H2Frame {
        H2Frame {
            len: 0,
            frame_type: FrameType::Data,
            flag: FrameFlag::default(),
            stream_identifier: 0,
            stream_dependency: 0,
            weight: 0,
            payload: vec![],
            settings: vec![],
        }
    }

    pub fn from_bytes(buffer: &mut Buffer) -> HlsResult<H2Frame> {
        if buffer.len() < 9 { return Err("byte not enough".into()); }
        let len = u32::from_be_bytes([0, buffer[0], buffer[1], buffer[2]]) as usize;
        let frame_type = FrameType::from_u8(buffer[3])?;
        let flag = FrameFlag::from_u8(buffer[4]);
        let mut stream_identifier = u32::from_be_bytes(buffer[5..9].try_into()?);
        stream_identifier &= !2147483648;
        if buffer.len() < 9 + len { return Err("byte not enough".into()); }
        let (dependency, weight, payload_range) = if flag.priority() {
            (u32::from_be_bytes(buffer[9..13].try_into()?), buffer[13], 14..9 + len)
        } else {
            (0, 0, 9..9 + len)
        };
        let mut payload: Vec<u8> = Vec::with_capacity(payload_range.end - payload_range.start);
        unsafe {
            let dst = payload.as_mut_ptr().add(0);
            ptr::copy_nonoverlapping(buffer[payload_range].as_ptr(), dst, len);
            payload.set_len(len);
        }
        buffer.copy_within(9 + len..buffer.len(), 0);
        buffer.set_len(buffer.len() - len - 9);


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
        writer.write_u8(self.frame_type as u8);
        let priority = self.flag.priority();

        writer.write_u8(self.flag.into_inner());
        writer.write_u32(self.stream_identifier, false);
        if priority {
            self.stream_dependency |= 2147483648;
            writer.write_u32(self.stream_dependency, false);
            writer.write_u8(self.weight);
        }
        writer.write_slice(self.payload.as_slice());
    }

    pub fn to_bytes(mut self) -> Vec<u8> {
        let mut res = (if self.flag.priority() { self.payload.len() + 5 } else { self.payload.len() } as u32).to_be_bytes()[1..].to_vec();
        res.push(self.frame_type.clone().to_u8());
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

    pub fn window_update() -> H2Frame {
        let mut frame = H2Frame::none_frame();
        frame.len = 4;
        frame.frame_type = FrameType::WindowUpdate;
        frame.payload = vec![0, 239, 0, 1];
        frame
    }

    pub fn default_setting() -> H2Frame {
        let settings = Setting::default();
        let mut payload = vec![];
        for setting in &settings {
            payload.extend(setting.to_bytes());
        }
        H2Frame {
            len: payload.len(),
            frame_type: FrameType::Settings,
            flag: FrameFlag::default(),
            stream_identifier: 0,
            stream_dependency: 0,
            weight: 0,
            settings,
            payload,
        }
    }

    pub fn new_header(hdr_bs: Vec<u8>, body_len: usize, sid: u32) -> H2Frame {
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

    pub fn new_body(mut body: Vec<u8>, sid: u32) -> Vec<H2Frame> {
        if body.is_empty() { return vec![]; }
        let max_len = u32::from_be_bytes([0, 255, 255, 255]) as usize;
        let mut res = vec![];
        loop {
            let pos = if body.len() >= max_len { max_len } else { body.len() };
            let payload = body[..pos].to_vec();
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
            body = body[pos..].to_vec();
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

    pub fn payload(&self) -> &Vec<u8> { &self.payload }
    pub fn to_payload(self) -> Vec<u8> { self.payload }

    pub fn set_payload(&mut self, payload: Vec<u8>) { self.payload = payload }

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