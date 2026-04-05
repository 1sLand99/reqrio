use crate::error::RlsResult;
use crate::extend::Aead;

pub struct PayloadDecodeBuffer<'a> {
    origin: &'a [u8],
    decoded: &'a mut [u8],
}


pub struct RecordDecodeBuffer<'a> {
    aead: &'a Aead,
    head: &'a [u8],
    payload: PayloadDecodeBuffer<'a>,
}

impl<'a> RecordDecodeBuffer<'a> {
    pub fn from_buffer(origin: &'a [u8], decoded: &'a mut [u8], aead: &'a Aead) -> RlsResult<Self> {
        let (head, origin) = origin.split_at(5);
        Ok(RecordDecodeBuffer {
            aead,
            head,
            payload: PayloadDecodeBuffer { origin, decoded },
        })
    }

    pub fn aad(&self, seq: u64) -> RlsResult<[u8; 13]> {
        let mut res = [0; 13];
        res[0..8].copy_from_slice(seq.to_be_bytes().as_ref());
        res[8] = self.head[0];
        res[9..11].copy_from_slice(&self.head[1..3]);
        let payload_len = self.payload.origin.len() as u16 - self.aead.explicit_len() as u16 - 16;
        res[11..13].copy_from_slice(&payload_len.to_be_bytes());
        Ok(res)
    }

    pub fn encrypted_payload(&self) -> &[u8] {
        match self.aead {
            Aead::AES_128_GCM | Aead::AES_256_GCM => &self.payload.origin[8..],
            Aead::ChaCha20_POLY1305 => self.payload.origin,
            Aead::AES_128_CBC_SHA | Aead::AES_256_CBC_SHA => &self.payload.origin[16..],
            _ => self.payload.origin
        }
    }

    pub fn explicit_iv(&self) -> &[u8] {
        match self.aead {
            Aead::AES_128_GCM | Aead::AES_256_GCM => &self.payload.origin[..8],
            Aead::AES_128_CBC_SHA | Aead::AES_256_CBC_SHA => &self.payload.origin[..16],
            _ => &self.payload.origin[..0]
        }
    }

    pub fn aead(&self) -> &Aead { self.aead }

    pub fn decrypted_buffer(&mut self) -> &mut [u8] {
        self.payload.decoded
    }

    pub fn head(&self) -> &[u8] { self.head }
}

