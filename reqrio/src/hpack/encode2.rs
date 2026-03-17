use core::slice;
use std::{mem};
use std::ptr::null_mut;
use libnghttp2::{nghttp2_hd_deflate_hd, nghttp2_hd_deflater, nghttp2_hd_inflate_hd2, nghttp2_hd_inflate_new, nghttp2_hd_inflater};
use crate::error::HlsResult;
use crate::hpack::HPackItem;

pub struct HackEncode {
    deflate: *mut nghttp2_hd_deflater,
    inflater: *mut nghttp2_hd_inflater,
}


impl HackEncode {
    pub fn new() -> HackEncode {
        let mut deflate = null_mut();
        unsafe { libnghttp2::nghttp2_hd_deflate_new(&mut deflate, 65535); }
        HackEncode {
            deflate,
            inflater: null_mut(),
        }
    }

    pub fn new_encode_size(size: u32) -> HackEncode {
        let mut deflate = null_mut();
        unsafe { libnghttp2::nghttp2_hd_deflate_new(&mut deflate, size as usize); }
        HackEncode {
            deflate,
            inflater: null_mut(),
        }
    }

    pub fn new_decode_size(size: u32) -> HackEncode {
        let mut inflater = null_mut();
        unsafe { nghttp2_hd_inflate_new(&mut inflater); }
        HackEncode {
            deflate: null_mut(),
            inflater,
        }
    }

    pub fn encode_one(&self, name: impl ToString, value: impl ToString) -> HlsResult<Vec<u8>> {
        let mut name = name.to_string();
        let mut value = value.to_string();
        let mut buf = [0; 2048];
        let hdr = libnghttp2::nghttp2_nv {
            name: name.as_mut_ptr(),
            value: value.as_mut_ptr(),
            namelen: name.len(),
            valuelen: value.len(),
            flags: 0,
        };

        let len = unsafe {
            nghttp2_hd_deflate_hd(
                self.deflate,
                buf.as_mut_ptr(),
                1024,
                [hdr].as_ptr(),
                1,
            )
        };
        if len > 2048 { return Ok(vec![]); }
        // println!("{:?}", &buf[..len as usize]);
        Ok(buf[..len as usize].to_vec())
    }

    pub fn decode(&self, buf: impl AsRef<[u8]>) -> HlsResult<Vec<HPackItem>> {
        let mut index = 0;
        let mut res = vec![];
        loop {
            let mut flag = 0;
            let mut nv_out = unsafe { mem::zeroed() };
            let ret = unsafe {
                nghttp2_hd_inflate_hd2(
                    self.inflater,
                    &mut nv_out,
                    &mut flag,
                    buf.as_ref()[index..].as_ptr(),
                    buf.as_ref()[index..].len(),
                    1,
                )
            };
            if nv_out.namelen != 0usize && nv_out.valuelen != 0 {
                let name = unsafe { slice::from_raw_parts(nv_out.name, nv_out.namelen) };
                let value = unsafe { slice::from_raw_parts(nv_out.value, nv_out.valuelen) };
                res.push(HPackItem::new(std::str::from_utf8(name)?, std::str::from_utf8(value)?));
            }
            index += ret as usize;
            if index >= buf.as_ref().len() { break; }
        }
        Ok(res)
    }
}

impl Drop for HackEncode {
    fn drop(&mut self) {
        if !self.deflate.is_null() {
            unsafe { libnghttp2::nghttp2_hd_deflate_del(self.deflate) };
        }
        if !self.inflater.is_null() {
            unsafe { libnghttp2::nghttp2_hd_inflate_del(self.inflater) }
        }
    }
}

unsafe impl Send for HackEncode {}
unsafe impl Sync for HackEncode {}

#[cfg(test)]
mod tests {
    use crate::hpack::HackEncode;

    #[test]
    fn test_nghttp() {
        let encode = HackEncode::new_encode_size(0xFFFF);
        let mut res = vec![];
        res.extend(encode.encode_one(":method", "GET").unwrap());
        res.extend(encode.encode_one(":path", "/api").unwrap());


        let hpack = HackEncode::new_decode_size(0xFFFF);
        println!("{:#?}", hpack.decode(res).unwrap());
    }
}