use crate::buffer::Buffer;
use crate::error::HlsResult;
use crate::hpack::HackDecode;
use crate::json::JsonValue;
use crate::packet::h2c::FrameType;
use crate::packet::{H2Frame, Header};
use crate::{coder, HeaderValue, CHUNK_END, HTTP_GAP};
use reqtls::WriteExt;
use std::{mem, ptr};

pub enum Body {
    Raw(Vec<u8>),
    Decoded(Vec<u8>),
    String(String),
    Json(JsonValue),
}

impl Body {
    fn extend(&mut self, buf: Vec<u8>) {
        match self {
            Body::Raw(raw) => raw.extend(buf),
            Body::Decoded(decoded) => decoded.extend(buf),
            Body::String(_) => {}
            Body::Json(_) => {}
        }
    }

    fn decompress(&mut self, encoding: Option<&HeaderValue>) -> HlsResult<()> {
        if let Body::Raw(raw) = self {
            let decoded = if let Some(encoding) = encoding {
                match encoding.as_string().unwrap_or("") {
                    "gzip" => coder::gzip_decompress(mem::take(raw))?,
                    "deflate" => coder::deflate_decompress(mem::take(raw))?,
                    "br" => coder::br_decompress(mem::take(raw))?,
                    "zstd" => coder::zstd_decompress(mem::take(raw))?,
                    _ => mem::take(raw),
                }
            } else {
                mem::take(raw)
            };
            *self = Body::Decoded(decoded);
        }
        Ok(())
    }

    pub fn as_json(&mut self) -> HlsResult<&JsonValue> {
        match self {
            Body::Decoded(decoded) => *self = Body::Json(crate::json::from_bytes(decoded).or(Err("decode to json error"))?),
            Body::String(string) => *self = Body::Json(crate::json::parse(string).or(Err("parse json error"))?),
            _ => {}
        };
        if let Body::Json(value) = self {
            Ok(value)
        } else { Err("not json body".into()) }
    }

    pub fn as_string(&mut self) -> HlsResult<&str> {
        match self {
            Body::Decoded(decoded) => *self = Body::String(String::from_utf8(mem::take(decoded)).or(Err("decode to string error"))?),
            Body::Json(j) => *self = Body::String(j.dump()),
            _ => {}
        };
        if let Body::String(value) = self {
            Ok(value)
        } else { Err("not json body".into()) }
    }

    fn into_string(self) -> HlsResult<String> {
        match self {
            Body::Raw(_) => Err("not decode".into()),
            Body::Decoded(decoded) => Ok(String::from_utf8(decoded)?),
            Body::String(value) => Ok(value),
            Body::Json(value) => Ok(value.dump())
        }
    }

    fn into_json(self) -> HlsResult<JsonValue> {
        match self {
            Body::Raw(_) => Err("not decode".into()),
            Body::Decoded(decoded) => Ok(crate::json::from_bytes(&decoded).or(Err("decode to json error"))?),
            Body::String(value) => Ok(crate::json::parse(value).or(Err("parse json error"))?),
            Body::Json(value) => Ok(value)
        }
    }

    fn is_raw(&self) -> bool {
        matches!(self, Body::Raw(_))
    }

    pub fn as_bytes(&self) -> HlsResult<&Vec<u8>> {
        match self {
            Body::Decoded(decoded) => Ok(decoded),
            _ => Err("not decode".into()),
        }
    }

    pub fn into_bytes(self) -> HlsResult<Vec<u8>> {
        match self {
            Body::Decoded(decoded) => Ok(decoded),
            _ => Err("not decode".into()),
        }
    }
}

pub struct Response {
    header: Header,
    body: Body,
    raw: Vec<u8>,
    frames: Vec<H2Frame>,
}

impl Default for Response {
    fn default() -> Self {
        Response {
            header: Header::new_res(),
            body: Body::Raw(Vec::new()),
            raw: Vec::new(),
            frames: vec![],
        }
    }
}

impl Response {
    pub fn new() -> Response {
        Response::default()
    }

    fn check_status(&self) -> Option<bool> {
        let chucked = self.header.get("transfer-encoding");
        if let Some(chucked) = chucked {
            if chucked.as_string()? != "chunked" {
                println!("have transfer-encoding, but unknow-{}", chucked.as_string()?);
                return None;
            }
            if self.raw.ends_with(&[48, 13, 10, 13, 10]) { return Some(true); }
            None
        } else {
            let len = self.header.content_length().unwrap_or(0);
            if self.raw.len() >= len { Some(true) } else { None }
        }
    }

    fn extend_body(&mut self, buffer: &mut Buffer) -> HlsResult<bool> {
        let copy_len = match self.header.content_length() {
            None => {
                let pos = buffer.filled().windows(CHUNK_END.len()).position(|w| w == CHUNK_END);
                pos.map(|pos| pos + CHUNK_END.len()).unwrap_or(buffer.len())
            }
            Some(len) => if buffer.len() < len - self.raw.len() { buffer.len() } else { len - self.raw.len() }
        };
        self.raw.reserve(copy_len);
        unsafe {
            let dst = self.raw.as_mut_ptr().add(self.raw.len());
            ptr::copy_nonoverlapping(buffer.filled().as_ptr(), dst, copy_len);
            self.raw.set_len(self.raw.len() + copy_len);
        }
        buffer.move_to(copy_len..buffer.len(), 0);
        Ok(self.check_status().unwrap_or(false))
    }

    pub fn extend_buffer(&mut self, buffer: &mut Buffer) -> HlsResult<bool> {
        match self.header.is_empty() {
            true => {
                let pos = buffer.filled().windows(HTTP_GAP.len()).position(|w| w == HTTP_GAP);
                if let Some(pos) = pos {
                    let hdr_str = String::from_utf8_lossy(&buffer[..pos]);
                    self.header = Header::try_from(hdr_str.as_ref())?;
                    buffer.move_to(pos + 4..buffer.len(), 0);
                    println!("{:?}", self.header.get("connection").map(|v| v.to_string()));
                    self.extend_body(buffer)
                } else { Ok(false) }
            }
            false => self.extend_body(buffer)
        }
    }

    pub fn extend_frame(&mut self, frame: H2Frame, hpack_coding: &mut HackDecode) -> HlsResult<bool> {
        let ended = frame.is_end_frame();
        match frame.frame_type() {
            FrameType::Data => self.raw.extend(frame.to_payload()),
            FrameType::Headers => {
                if frame.flag().end_header() {
                    let mut payload = self.frames.drain(..).map(|x| x.to_payload()).collect::<Vec<_>>();
                    payload.push(frame.to_payload());
                    let mut hdr_bs = payload.concat();
                    let res = hpack_coding.decode(&mut hdr_bs)?;
                    self.header = Header::parse_h2(res)?;
                    println!("{:?}", self.header.get("connection").map(|v| v.to_string()));
                } else {
                    self.frames.push(frame);
                }
            }
            _ => {}
        }
        Ok(ended)
    }

    pub fn push_raw(&mut self, raw: Vec<u8>) {
        self.raw.extend(raw)
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn header_mut(&mut self) -> &mut Header { &mut self.header }

    pub fn raw_body(&self) -> &[u8] { &self.raw }

    pub fn raw_string(&self) -> String {
        let header = self.header.to_string();
        let body = String::from_utf8_lossy(&self.raw);
        header + "\r\n\r\n" + body.as_ref()
    }

    pub fn clear_raw(&mut self) { self.raw.clear() }

    pub fn decode_body(&mut self) -> HlsResult<&mut Body> {
        if !self.body.is_raw() { return Ok(&mut self.body); }
        let chucked = self.header.get("transfer-encoding");
        if let Some(chucked) = chucked && chucked.as_string().unwrap_or("") == "chunked" {
            self.body.extend(coder::chunk_decode(mem::take(&mut self.raw))?);
        } else {
            self.body.extend(mem::take(&mut self.raw));
        }
        let encoding = self.header.get("content-encoding");
        self.body.decompress(encoding)?;
        Ok(&mut self.body)
    }

    pub fn json(mut self) -> HlsResult<JsonValue> {
        self.decode_body()?;
        self.body.into_json()
    }

    pub fn text(mut self) -> HlsResult<String> {
        self.decode_body()?;
        self.body.into_string()
    }

    pub fn bytes(mut self) -> HlsResult<Vec<u8>> {
        self.decode_body()?;
        self.body.into_bytes()
    }
}