use std::ops::Range;
use crate::extend::Aead;
use crate::{RecordType, Version};

pub struct PayloadEncodeBuffer<'a> {
    payload: &'a mut [u8],
    plain_offset: Range<usize>,
    encode_offset: Range<usize>,
}
impl<'a> PayloadEncodeBuffer<'a> {
    pub fn new(aead: &Aead, version: &Version, ct: &RecordType, buffer: &'a mut [u8], origin: &[u8]) -> PayloadEncodeBuffer<'a> {
        let explicit_len = aead.explicit_len(version);
        let mut plain_offset = explicit_len..explicit_len + origin.len();
        buffer[plain_offset.clone()].copy_from_slice(origin);
        if *version == Version::TLS_1_3 {
            buffer[plain_offset.end] = ct.as_u8();
            plain_offset.end += 1
        }
        PayloadEncodeBuffer {
            payload: buffer,
            encode_offset: explicit_len..explicit_len + plain_offset.len() + 16,
            plain_offset,

        }
    }

    fn add_explicit_iv(&mut self, aead: &Aead, version: &Version, iv: &[u8]) {
        match aead {
            Aead::AES_128_GCM | Aead::AES_256_GCM => match *version {
                Version::TLS_1_3 => {}
                _ => self.payload[..8].copy_from_slice(&iv[4..])
            },
            Aead::ChaCha20_POLY1305 => {}
            Aead::AES_128_CBC_SHA | Aead::AES_256_CBC_SHA => self.payload[..16].copy_from_slice(&iv[..16]),
            _ => panic!("unsupported suite specification"),
        };
    }

    pub fn origin_payload(&self) -> &[u8] {
        &self.payload[self.plain_offset.clone()]
    }

    pub fn encoded_payload(&mut self) -> &mut [u8] {
        &mut self.payload[self.encode_offset.clone()]
    }
}

pub struct RecordEncodeBuffer<'a> {
    aead: &'a Aead,
    head: &'a mut [u8],
    record_len: usize,
    payload: PayloadEncodeBuffer<'a>,
    version: &'a Version,
}


impl<'a> RecordEncodeBuffer<'a> {
    pub(crate) fn new(rt: RecordType, version: &'a Version, buffer: &'a mut [u8], origin: &'a [u8], aead: &'a Aead) -> RecordEncodeBuffer<'a> {
        let (head, payload) = buffer.split_at_mut(5);
        head[0] = match *version {
            Version::TLS_1_3 => 23,
            _ => rt.as_u8()
        };
        head[1] = 3;
        head[2] = 3;
        RecordEncodeBuffer {
            aead,
            head,
            record_len: 0,
            payload: PayloadEncodeBuffer::new(aead, version, &rt, payload, origin),
            version,
        }
    }

    pub fn payload(&mut self) -> &mut PayloadEncodeBuffer<'a> {
        &mut self.payload
    }

    pub fn add_explicit_iv(&mut self, iv: &[u8]) {
        self.payload.add_explicit_iv(self.aead, self.version, iv)
    }

    pub fn set_encrypted_len(&mut self, len: usize) {
        let len = self.aead.explicit_len(self.version) + len;
        self.record_len = len + 5;
        self.head[3..5].copy_from_slice(&(len as u16).to_be_bytes());
    }

    pub fn head(&self) -> &[u8] { self.head }

    pub fn aad(&self, seq: u64) -> Vec<u8> {
        match *self.version {
            Version::TLS_1_3 => self.tls13_aad(),
            _ => self.tls12_aad(seq)
        }
    }

    fn tls13_aad(&self) -> Vec<u8> {
        let mut res = vec![0; 5];
        res[0..3].copy_from_slice(&self.head[0..3]);
        let len = self.payload.encode_offset.len() as u16;
        res[3..5].copy_from_slice(&len.to_be_bytes());
        res
    }

    fn tls12_aad(&self, seq: u64) -> Vec<u8> {
        let mut res = vec![0; 13];
        let ptr = res.as_mut_ptr() as *mut u64;
        unsafe { ptr.write_unaligned(seq); }
        res[0..8].copy_from_slice(&seq.to_be_bytes());
        res[8..11].copy_from_slice(&self.head[..3]);
        res[11..13].copy_from_slice(&(self.payload.plain_offset.len() as u16).to_be_bytes());
        res
    }

    pub fn record_len(&self) -> usize { self.record_len }
}


#[cfg(test)]
mod tests {
    use crate::buffer::RecordEncodeBuffer;
    use crate::{RecordType, Version};
    use crate::extend::Aead;

    #[test]
    fn test_encode_buffer() {
        let mut buffer = [0; 1024];
        let payload = (1..100).collect::<Vec<u8>>();
        let version = Version::TLS_1_2;
        let record_type = RecordType::ApplicationData;

        let aead = Aead::AES_128_GCM;
        let mut encode = RecordEncodeBuffer::new(record_type, &version, &mut buffer, &payload, &aead);
        encode.add_explicit_iv(&[14; 12]);
        assert_eq!(encode.head(), [record_type.as_u8(), 3, 3, 0, 0]);
        assert_eq!(encode.payload.origin_payload(), payload);
        let mut pd = Vec::with_capacity(aead.explicit_len(&version) + payload.len() + 16);
        pd.extend_from_slice(&payload);
        pd.extend([0; 16]);
        assert_eq!(encode.payload.encoded_payload(), pd);

        let aead = Aead::ChaCha20_POLY1305;
        let mut buffer = [0; 1024];
        let mut encode = RecordEncodeBuffer::new(record_type, &version, &mut buffer, &payload, &aead);
        assert_eq!(encode.head(), [record_type.as_u8(), 3, 3, 0, 0]);
        assert_eq!(encode.payload.origin_payload(), payload);
        assert_eq!(encode.payload.encoded_payload(), pd);

        let aead = Aead::AES_128_CBC_SHA;
        let mut buffer = [0; 1024];
        let mut encode = RecordEncodeBuffer::new(record_type, &version, &mut buffer, &payload, &aead);
        encode.add_explicit_iv(&[77; 16]);
        assert_eq!(encode.head(), [record_type.as_u8(), 3, 3, 0, 0]);
        assert_eq!(encode.payload.origin_payload(), payload);
        assert_eq!(encode.payload.encoded_payload(), pd);
    }

    #[test]
    fn test_tls13_buffer() {
        let mut buffer = [0; 1024];
        let payload = (1..100).collect::<Vec<u8>>();
        let version = Version::TLS_1_3;
        let record_type = RecordType::HandShake;

        let aead = Aead::AES_128_GCM;
        let mut encode = RecordEncodeBuffer::new(record_type, &version, &mut buffer, &payload, &aead);
        encode.add_explicit_iv(&[14; 12]);
        assert_eq!(encode.head(), [23, 3, 3, 0, 0]);
        let mut pd = Vec::with_capacity(aead.explicit_len(&version) + payload.len() + 16);
        pd.extend_from_slice(&payload);
        pd.push(record_type.as_u8());
        assert_eq!(encode.payload.origin_payload(), pd);
        pd.extend([0; 16]);
        assert_eq!(encode.payload.encoded_payload(), pd);


        let aead = Aead::ChaCha20_POLY1305;
        let mut buffer = [0; 1024];
        let mut encode = RecordEncodeBuffer::new(record_type, &version, &mut buffer, &payload, &aead);
        assert_eq!(encode.head(), [23, 3, 3, 0, 0]);
        pd = pd[..pd.len() - 16].to_vec();
        assert_eq!(encode.payload.origin_payload(), pd);
        pd.extend([0; 16]);
        assert_eq!(encode.payload.encoded_payload(), pd);
    }
}