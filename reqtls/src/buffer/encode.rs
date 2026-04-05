use crate::extend::Aead;
use crate::{RecordType, Version};

pub struct PayloadEncodeBuffer<'a> {
    encoded: &'a mut [u8],
    origin: &'a [u8],
}

impl<'a> PayloadEncodeBuffer<'a> {
    pub fn add_explicit_iv(&mut self, aead: &Aead, iv: &[u8]) {
        match aead {
            Aead::AES_128_GCM | Aead::AES_256_GCM => self.encoded[..8].copy_from_slice(&iv[4..]),
            Aead::ChaCha20_POLY1305 => {}
            Aead::AES_128_CBC_SHA | Aead::AES_256_CBC_SHA => self.encoded[..16].copy_from_slice(&iv[..16]),
            _ => panic!("unsupported suite specification"),
        };
    }
}

pub struct RecordEncodeBuffer<'a> {
    aead: &'a Aead,
    head: &'a mut [u8],
    record_len: usize,
    payload: PayloadEncodeBuffer<'a>,
}


impl<'a> RecordEncodeBuffer<'a> {
    pub(crate) fn new(rt: RecordType, version: &Version, buffer: &'a mut [u8], origin: &'a [u8], aead: &'a Aead) -> RecordEncodeBuffer<'a> {
        let (head, payload) = buffer.split_at_mut(5);
        head[0] = rt as u8;
        head[1] = (version.0 >> 8 & 255) as u8;
        head[2] = (version.0 & 255) as u8;
        RecordEncodeBuffer {
            aead,
            head,
            record_len: 0,
            payload: PayloadEncodeBuffer {
                encoded: payload,
                origin,
            },
        }
    }

    pub fn add_explicit_iv(&mut self, iv: &[u8]) {
        self.payload.add_explicit_iv(self.aead, iv)
    }

    pub fn origin_payload(&self) -> &[u8] {
        self.payload.origin
    }

    pub fn set_encrypted_len(&mut self, len: usize) {
        let len = self.aead.explicit_len() + len;
        self.record_len = len + 5;
        self.head[3..5].copy_from_slice(&(len as u16).to_be_bytes());
    }

    pub fn encrypted_buffer(&mut self) -> &mut [u8] {
        match self.aead {
            Aead::AES_128_GCM | Aead::AES_256_GCM => &mut self.payload.encoded[8..],
            Aead::ChaCha20_POLY1305 => self.payload.encoded,
            Aead::AES_128_CBC_SHA | Aead::AES_256_CBC_SHA => &mut self.payload.encoded[16..],
            _ => self.payload.encoded
        }
    }

    pub fn head(&self) -> &[u8] { self.head }

    pub fn aad(&self, seq: u64) -> [u8; 13] {
        let mut res = [0; 13];
        let ptr=res.as_mut_ptr() as *mut u64;
        unsafe { ptr.write_unaligned(seq); }
        res[0..8].copy_from_slice(&seq.to_be_bytes());
        res[8..11].copy_from_slice(&self.head[..3]);
        res[11..13].copy_from_slice(&(self.payload.origin.len() as u16).to_be_bytes());
        res
    }

    pub fn record_len(&self) -> usize { self.record_len }
}