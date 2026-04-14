use crate::error::RlsResult;
use crate::extend::Aead;
use crate::Version;

pub struct PayloadDecodeBuffer<'a> {
    origin: &'a [u8],
    decoded: &'a mut [u8],
}


pub struct RecordDecodeBuffer<'a> {
    aead: &'a Aead,
    head: &'a [u8],
    payload: PayloadDecodeBuffer<'a>,
    version: &'a Version,
}

impl<'a> RecordDecodeBuffer<'a> {
    pub fn from_buffer(origin: &'a [u8], decoded: &'a mut [u8], aead: &'a Aead, version: &'a Version) -> RlsResult<Self> {
        let (head, origin) = origin.split_at(5);
        Ok(RecordDecodeBuffer {
            aead,
            head,
            payload: PayloadDecodeBuffer { origin, decoded },
            version,
        })
    }

    pub fn aad(&self, seq: u64) -> RlsResult<Vec<u8>> {
        match *self.version {
            Version::TLS_1_3 => Ok(self.tls13_aad()),
            Version::TLS_1_2 => Ok(self.tls12_aad(seq)),
            _ => Err("Unsupported version".into()),
        }
    }

    ///tls1.2 aad: seq||head[0..3]||pd_len(not tag)
    fn tls12_aad(&self, seq: u64) -> Vec<u8> {
        let mut res = vec![0; 13];
        res[0..8].copy_from_slice(seq.to_be_bytes().as_ref());
        res[8] = self.head[0];
        res[9..11].copy_from_slice(&self.head[1..3]);
        let payload_len = self.payload.origin.len() as u16 - self.aead.explicit_len(self.version) as u16 - 16;
        res[11..13].copy_from_slice(&payload_len.to_be_bytes());
        res
    }

    ///tls1.3 aad: head[0..3]||pd_len(tag)
    fn tls13_aad(&self) -> Vec<u8> {
        let mut res = vec![0; 5];
        res[0..3].copy_from_slice(&self.head[0..3]);
        let payload_len = self.payload.origin.len() as u16;
        res[3..5].copy_from_slice(&payload_len.to_be_bytes());
        res
    }

    pub fn encrypted_payload(&self) -> &[u8] {
        match self.aead {
            Aead::AES_128_GCM | Aead::AES_256_GCM => match *self.version {
                Version::TLS_1_3 => &self.payload.origin[0..],
                _ => &self.payload.origin[8..],
            },
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

    pub fn version(&self) -> &Version { self.version }
}

