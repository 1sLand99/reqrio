use crate::extend::Aead;
use std::fmt::Debug;


pub struct Payload<'a> {
    //真实payload长度，不含explicit和tag等信息
    pub(crate) len: usize,
    pub(crate) value: &'a mut [u8],
}

impl<'a> Payload<'a> {
    pub fn encrypting_out(&mut self, aead: &Aead) -> &mut [u8] {
        match aead {
            Aead::AES_128_GCM | Aead::AES_256_GCM => &mut self.value[8..],
            Aead::ChaCha20_POLY1305 => self.value,
            Aead::AES_128_CBC_SHA | Aead::AES_256_CBC_SHA => &mut self.value[16..],
            _ => self.value
        }
    }

    pub fn encrypting_in(&self, aead: &Aead) -> &[u8] {
        match aead {
            Aead::AES_128_GCM | Aead::AES_256_GCM => &self.value[8..8 + self.len],
            Aead::ChaCha20_POLY1305 => &self.value[..self.len],
            Aead::AES_128_CBC_SHA | Aead::AES_256_CBC_SHA => &self.value[16..16 + self.len],
            _ => &self.value[..self.len]
        }
    }

    pub fn decrypting_payload(&mut self, aead: &Aead) -> &mut [u8] {
        let len = self.value.len();
        match aead {
            Aead::AES_128_GCM | Aead::AES_256_GCM => &mut self.value[8..],
            Aead::ChaCha20_POLY1305 => self.value,
            Aead::AES_128_CBC_SHA | Aead::AES_256_CBC_SHA => &mut self.value[16..len - 20],
            _ => self.value
        }
    }

    pub fn explicit_iv(&self, aead: &Aead) -> &[u8] {
        match aead {
            Aead::AES_128_GCM | Aead::AES_256_GCM => &self.value[..8],
            Aead::AES_128_CBC_SHA | Aead::AES_256_CBC_SHA => &self.value[..16],
            _ => &self.value[..0]
        }
    }

    pub fn from_slice(slice: &'a mut [u8]) -> Payload<'a> {
        Payload {
            len: 0,
            value: slice,
        }
    }
}

impl<'a> Debug for Payload<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(hex::encode(&self.value).as_str())
    }
}