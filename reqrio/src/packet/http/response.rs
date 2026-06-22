use std::mem;
use crate::body::H2FrameRBuf;
use crate::error::HlsResult;
use crate::hpack::HPackDecode;
use crate::json::JsonValue;
use crate::*;
use reqtls::coder::{BrotliDecoder, ChunkDecoder, CodingError, DeflateStream, StreamDecode, ZstdDecoder};
use std::str::Utf8Error;

pub struct Response {
    header: Header,
    raw: Buffer,
    coder: Option<Box<dyn StreamDecode<Buffer> + Send + Sync>>,
    read_size: usize,
    h2_buffer: Buffer,
}

impl Default for Response {
    fn default() -> Self {
        Response {
            header: Header::new_res(),
            raw: Buffer::with_capacity(8192),
            coder: None,
            read_size: 0,
            h2_buffer: Buffer::with_capacity(8192),
        }
    }
}

impl Response {
    pub fn new() -> Response {
        Response::default()
    }

    fn extend_body(&mut self, buffer: &mut Buffer) -> HlsResult<bool> {
        match self.coder {
            None => {
                let len = self.header.content_length().unwrap_or(0);
                let read_len = if self.raw.len() + buffer.len() >= len { len - self.raw.len() } else { buffer.len() };
                loop {
                    match self.raw.write_slice(&buffer.filled()[..read_len]) {
                        Ok(_) => break,
                        Err(BufferError::CapacityTooSmall { .. }) => {
                            self.raw.resize(self.raw.capacity() * 2)?;
                        }
                        Err(e) => return Err(e.into()),
                    }
                }
                buffer.used_empty(read_len);
                Ok(self.raw.len() >= len)
            }
            Some(ref mut coder) => {
                let mut reader = Reader::from_slice(buffer.filled());
                loop {
                    let res = if reader.unread_len() == 0 && reader.position() != 0 {
                        coder.flush(&mut self.raw)
                    } else {
                        coder.decompress(&mut reader, &mut self.raw)
                    };
                    match res {
                        Ok(_) => break,
                        Err(CodingError::Buffer(BufferError::CapacityTooSmall { .. })) => {
                            self.raw.resize(self.raw.capacity() * 2)?;
                        }
                        Err(e) => return Err(e.into()),
                    }
                };
                println!("{} {}", reader.position(), self.raw.len());
                self.read_size += reader.position();
                buffer.used_empty(reader.position());
                let len = self.header.content_length().unwrap_or(0);
                Ok(coder.finish() || (len != 0 && self.read_size >= len))
            }
        }
    }

    fn make_coding(&mut self) -> HlsResult<()> {
        let chunked = self.header.get_str("transfer-encoding").unwrap_or("").trim();
        let encoding = self.header.content_encoding().unwrap_or("").trim();
        #[cfg(feature = "log")]
        debug!("[Response] make coding: chunk={}; encoding={}", chunked=="chunked", encoding);
        match (chunked, encoding) {
            ("chunked", "gzip") => {
                let gzip = DeflateStream::new_decompress(DeflateStream::GZIP)?;
                let coding = ChunkDecoder::new(gzip);
                self.coder = Some(Box::new(coding))
            }
            ("chunked", "deflate") => {
                let deflate = DeflateStream::new_decompress(DeflateStream::DEFLATE)?;
                let coding = ChunkDecoder::new(deflate);
                self.coder = Some(Box::new(coding))
            }
            ("chunked", "br") => {
                let coding = ChunkDecoder::new(BrotliDecoder::new()?);
                self.coder = Some(Box::new(coding))
            }
            ("chunked", "zstd") => {
                let coding = ChunkDecoder::new(ZstdDecoder::new()?);
                self.coder = Some(Box::new(coding))
            }
            ("chunked", "") => self.coder = Some(Box::new(ChunkDecoder::new(()))),
            (_, "gzip") => self.coder = Some(Box::new(DeflateStream::new_decompress(DeflateStream::GZIP)?)),
            (_, "deflate") => self.coder = Some(Box::new(DeflateStream::new_decompress(DeflateStream::DEFLATE)?)),
            (_, "br") => self.coder = Some(Box::new(BrotliDecoder::new()?)),
            (_, "zstd") => self.coder = Some(Box::new(ZstdDecoder::new()?)),
            (_, _) => {}
        }
        Ok(())
    }

    pub fn extend_buffer(&mut self, buffer: &mut Buffer) -> HlsResult<bool> {
        match self.header.is_empty() {
            true => {
                let pos = buffer.filled().windows(HTTP_GAP.len()).position(|w| w == HTTP_GAP);
                let Some(pos) = pos else { return Ok(false) };
                let hdr_str = std::str::from_utf8(&buffer.filled()[..pos])?;
                self.header = Header::try_from(hdr_str)?;
                buffer.used_empty(pos + HTTP_GAP.len());
                self.make_coding()?;
                self.extend_body(buffer)
            }
            false => self.extend_body(buffer)
        }
    }

    pub fn extend_frame(&mut self, frame: &H2FrameRBuf, decoder: &mut HPackDecode) -> HlsResult<bool> {
        let ended = frame.is_end_frame();
        match frame.frame_type() {
            FrameType::Data => {
                let mut buffer = mem::replace(&mut self.h2_buffer, Buffer::with_capacity(0));
                let ret = buffer.check_move(frame.payload().len());
                if ret.is_err() || buffer.unfilled_len() < frame.payload().len() {
                    buffer.resize(buffer.capacity() * 2 + frame.payload().len())?;
                }
                buffer.write_slice(frame.payload())?;
                self.extend_body(&mut buffer)?;
                drop(mem::replace(&mut self.h2_buffer, buffer));
            }
            FrameType::Headers => {
                decoder.decode_into(frame.payload(), &mut self.header)?;
                self.make_coding()?;
            }
            _ => {}
        }
        Ok(ended)
    }

    // pub fn push_raw_slice(&mut self, raw: &[u8]) {
    //     self.raw.extend_from_slice(raw)
    // }

    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn header_mut(&mut self) -> &mut Header { &mut self.header }

    pub fn set_header(&mut self, header: Header) {
        self.header = header
    }

    pub fn raw_string(&self) -> String {
        let mut header = self.header.to_string();
        let body = self.as_text().unwrap_or("(二进制数据)");
        if self.header.alpn() != &ALPN::Http11 {
            header += "\r\n\r\n";
        }
        header + body
    }

    pub fn json(self) -> HlsResult<JsonValue> {
        Ok(json::from_bytes(self.raw.filled())?)
    }

    pub fn as_text(&self) -> Result<&str, Utf8Error> {
        println!("11={}", self.raw.len());
        std::str::from_utf8(self.raw.filled())
    }

    pub fn text(self) -> Result<String, Utf8Error> {
        Ok(self.as_text()?.to_owned())
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.raw.filled()
    }

    pub fn bytes(self) -> Vec<u8> {
        self.raw.filled().to_vec()
    }
}