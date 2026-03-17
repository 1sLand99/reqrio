use crate::error::HlsResult;
pub use crate::hpack::encode2::HackEncode;
pub use error::HPackError;
pub use item::HPackItem;
pub use encode::HpackEncode;

mod encode;
mod error;
mod encode2;
mod item;
mod table;
mod index;
mod huffman;
// pub struct HackEncode(httlib_hpack::Encoder<'static>);
//
// impl HackEncode {
//     pub fn new() -> HackEncode {
//         HackEncode(httlib_hpack::Encoder::with_dynamic_size(65535))
//     }
//
//     pub fn encode_packs(&mut self, packs: &Vec<HPack>) -> HlsResult<Vec<u8>> {
//         let mut res = vec![];
//         for pack in packs {
//             let flag = Encoder::HUFFMAN_VALUE | Encoder::WITH_INDEXING | Encoder::BEST_FORMAT; // 0x2 | 0x4 | 0x10
//             let value = (pack.name().as_bytes().to_vec(), pack.value().as_bytes().to_vec(), flag);
//             let mut dst = vec![];
//             self.0.encode(value, &mut dst).unwrap();
//             res.extend(dst)
//         }
//         Ok(res)
//     }
//
//     pub fn encode(&mut self, hks: Vec<HeaderKey>) -> HlsResult<Vec<u8>> {
//         let mut res = vec![];
//         for hk in hks {
//             let name = hk.name().to_lowercase();
//             match hk.value() {
//                 HeaderValue::Cookies(cookies) => {
//                     for cookie in cookies {
//                         let value = cookie.as_req();
//                         let mut dst = vec![];
//                         self.0.encode((name.as_bytes().to_vec(), value.into_bytes(), 0x2 | 0x4 | 0x10), &mut dst).unwrap();
//                         // res.extend(self.0.encode((name.as_bytes().to_vec(), value.into_bytes(), 0x2 | 0x4 | 0x10))?);
//                         res.extend(dst);
//                     }
//                 }
//                 _ => {
//                     let value = hk.value().to_string();
//                     let mut dst = vec![];
//                     self.0.encode((name.as_bytes().to_vec(), value.into_bytes(), 0x2 | 0x4 | 0x10), &mut dst).unwrap();
//                     res.extend(dst);
//                 }
//             }
//         }
//         Ok(res)
//     }
//
//     pub fn encode_one(&mut self, name: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) -> HlsResult<Vec<u8>> {
//         let mut dst = vec![];
//         self.0.encode((name.into(), value.into(), 0x2 | 0x4 | 0x10), &mut dst).unwrap();
//         Ok(dst)
//     }
//
//     pub fn new_size(size: u32) -> HackEncode {
//         HackEncode(httlib_hpack::Encoder::with_dynamic_size(size))
//     }
// }

// pub struct HackDecode(httlib_hpack::Decoder<'static>);
//
// impl HackDecode {
//     pub fn new() -> HackDecode {
//         HackDecode(httlib_hpack::Decoder::with_dynamic_size(65535))
//     }
//     pub fn decode(&mut self, buf: &mut Vec<u8>) -> HlsResult<Vec<HPack>> {
//         let mut dst = vec![];
//         self.0.decode(buf, &mut dst)?;
//         let mut res = vec![];
//         for (name, value, flag) in dst {
//             let name = String::from_utf8(name)?;
//             let value = String::from_utf8(value)?;
//             res.push(HPack::new_flag(name, value, flag));
//         }
//         Ok(res)
//     }
//
//     pub fn new_size(size: u32) -> HackDecode {
//         HackDecode(httlib_hpack::Decoder::with_dynamic_size(size))
//     }
// }

pub struct HPackCoding {
    decoder: HackEncode,
    encoder: encode::HpackEncode,
}

impl HPackCoding {
    pub fn new() -> HPackCoding {
        HPackCoding {
            decoder: HackEncode::new_decode_size(65536),
            encoder: encode::HpackEncode::new(65536),
        }
    }

    pub fn decode(&mut self, context: &mut Vec<u8>) -> HlsResult<Vec<HPackItem>> {
        Ok(self.decoder.decode(context)?)
    }

    // pub fn encode(&mut self, headers: Vec<HeaderKey>) -> HlsResult<Vec<u8>> {
    //     self.encoder.encode(headers)
    // }

    pub fn encoder(&mut self) -> &mut encode::HpackEncode { &mut self.encoder }

    pub fn decoder(&mut self) -> &mut HackEncode { &mut self.decoder }
}

impl Clone for HPackCoding {
    fn clone(&self) -> Self {
        HPackCoding::new()
    }
}