use httlib_hpack::Encoder;
pub use table2::HPack;
pub use error::HPackError;
use crate::error::HlsResult;
use crate::HeaderValue;
use crate::packet::HeaderKey;

mod encoder;
mod table2;
mod table;
mod error;

pub struct HackEncode(encoder::Encoder<'static>);

impl HackEncode {
    pub fn new() -> HackEncode {
        HackEncode(encoder::Encoder::with_dynamic_size(0xFFFF))
    }

    pub fn encode_packs(&mut self, packs: &Vec<HPack>) -> HlsResult<Vec<u8>> {
        let mut res = vec![];
        for pack in packs {
            let flag = Encoder::HUFFMAN_VALUE | Encoder::WITH_INDEXING | Encoder::BEST_FORMAT; // 0x2 | 0x4 | 0x10
            let value = (pack.name().as_bytes().to_vec(), pack.value().as_bytes().to_vec(), flag);
            res.extend(self.0.encode(value)?)
        }
        Ok(res)
    }

    pub fn encode(&mut self, hks: Vec<HeaderKey>) -> HlsResult<Vec<u8>> {
        let mut res = vec![];
        for hk in hks {
            let name = hk.name().to_lowercase();
            match hk.value() {
                HeaderValue::Cookies(cookies) => {
                    for cookie in cookies {
                        let value = cookie.as_req();
                        res.extend(self.0.encode((name.as_bytes().to_vec(), value.into_bytes(), 0x2 | 0x4 | 0x10))?);
                    }
                }
                _ => {
                    let value = hk.value().to_string();
                    res.extend(self.0.encode((name.into_bytes(), value.into_bytes(), 0x2 | 0x4 | 0x10))?);
                }
            }
        }
        Ok(res)
    }

    pub fn encode_one(&mut self, name: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) -> HlsResult<Vec<u8>> {
        Ok(self.0.encode((name.into(), value.into(), 0x2 | 0x4 | 0x10))?)
    }
}

pub struct HackDecode(httlib_hpack::Decoder<'static>);

impl HackDecode {
    pub fn new() -> HackDecode {
        HackDecode(httlib_hpack::Decoder::with_dynamic_size(0xFFFF))
    }
    pub fn decode(&mut self, buf: &mut Vec<u8>) -> HlsResult<Vec<HPack>> {
        let mut dst = vec![];
        self.0.decode(buf, &mut dst)?;
        let mut res = vec![];
        for (name, value, flag) in dst {
            let name = String::from_utf8(name)?;
            let value = String::from_utf8(value)?;
            res.push(HPack::new_flag(name, value, flag));
        }
        Ok(res)
    }
}

pub struct HPackCoding {
    decoder: HackDecode,
    encoder: HackEncode,
}

impl HPackCoding {
    pub fn new() -> HPackCoding {
        HPackCoding {
            decoder: HackDecode::new(),
            encoder: HackEncode::new(),
        }
    }

    pub fn decode(&mut self, context: &mut Vec<u8>) -> HlsResult<Vec<HPack>> {
        Ok(self.decoder.decode(context)?)
    }

    pub fn encode(&mut self, headers: Vec<HeaderKey>) -> HlsResult<Vec<u8>> {
        self.encoder.encode(headers)
    }

    pub fn encoder(&mut self) -> &mut HackEncode { &mut self.encoder }

    pub fn decoder(&mut self) -> &mut HackDecode { &mut self.decoder }
}

impl Clone for HPackCoding {
    fn clone(&self) -> Self {
        HPackCoding::new()
    }
}