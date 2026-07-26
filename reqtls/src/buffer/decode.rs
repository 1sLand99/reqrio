use crate::error::RlsResult;
use crate::{BufferError, CipherSuite, CipherType, Version};
use crate::message::QUICPacket;
use crate::suite::iv::Iv;

pub struct PayloadDecodeBuffer<'a> {
    origin: &'a [u8],
    decoded: &'a mut [u8],
}


pub struct CipherDecodeBuffer<'a> {
    suite: &'static CipherSuite,
    quic: bool,
    head: &'a [u8],
    payload: PayloadDecodeBuffer<'a>,
}

impl<'a> CipherDecodeBuffer<'a> {
    pub fn from_buffer(origin: &'a [u8], decoded: &'a mut [u8], suite: &'static CipherSuite) -> RlsResult<Self> {
        if decoded.len() < origin.len() - 5 {
            return Err(BufferError::CapacityTooSmall {
                current: decoded.len(),
                file: file!(),
                needed: origin.len(),
                line: line!(),
            }.into());
        }
        let (head, origin) = origin.split_at(5);
        Ok(CipherDecodeBuffer {
            suite,
            quic: false,
            head,
            payload: PayloadDecodeBuffer { origin, decoded },
        })
    }

    pub fn from_quic(packet: &'a QUICPacket, decoded: &'a mut [u8]) -> RlsResult<Self> {
        Ok(CipherDecodeBuffer {
            head: packet.hdr_raw(),
            suite: &CipherSuite::TLS_AES_128_GCM_SHA256,
            payload: PayloadDecodeBuffer { origin: packet.payload.as_ref(), decoded },
            quic: true,
        })
    }

    pub fn aad(&self, seq: u64) -> RlsResult<Vec<u8>> {
        if self.quic { return Ok(self.head.to_vec()); }
        match *self.suite.version {
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
        let payload_len = self.payload.origin.len() as u16 - self.suite.trans_iv_len as u16 - 16;
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
        &self.payload.origin[self.suite.trans_iv_len..]
    }

    pub fn explicit_iv(&self) -> &[u8] {
        &self.payload.origin[..self.suite.trans_iv_len]
    }

    pub fn decrypted_buffer(&mut self) -> &mut [u8] {
        self.payload.decoded
    }

    pub fn head(&self) -> &[u8] { self.head }

    pub fn nonce(&self, iv: &Iv, seq: u64) -> Vec<u8> {
        match self.suite.cipher() {
            CipherType::AES_128_GCM | CipherType::AES_256_GCM => match *self.suite.version {
                Version::TLS_1_3 => iv.as_array(seq, Some(self.explicit_iv())),
                _ => iv.decrypting_iv(Some(self.explicit_iv())).into_owned()
            },
            CipherType::CHACHA20_POLY1305 => iv.as_array(seq, Some(self.explicit_iv())),
            CipherType::AES_128_CBC | CipherType::AES_256_CBC => iv.decrypting_iv(Some(self.explicit_iv())).into_owned(),
            _ => panic!("gen iv failed"),
        }
    }
}

