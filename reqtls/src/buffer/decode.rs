use std::slice;
use crate::error::RlsResult;
use crate::{BufferError, CipherSuite, CipherType, Version};
#[cfg(feature = "quic")]
use crate::message::QUICPacket;
use crate::suite::iv::Iv;

#[repr(C)]
pub struct TlsDecodeBuffer {
    suite: &'static CipherSuite,
    quic: bool,
    head_len: usize,
    head: *const u8,
    origin_len: usize,
    origin: *const u8,
    decoded: *mut u8,
}

impl TlsDecodeBuffer {
    pub fn from_buffer(origin: &[u8], decoded: &mut [u8], suite: &'static CipherSuite) -> RlsResult<Self> {
        if decoded.len() < origin.len() - 5 - suite.trans_iv_len {
            return Err(BufferError::CapacityTooSmall {
                current: decoded.len(),
                file: file!(),
                needed: origin.len(),
                line: line!(),
            }.into());
        }
        let (head, origin) = origin.split_at(5);
        Ok(TlsDecodeBuffer {
            suite,
            quic: false,
            head_len: 5,
            head: head.as_ptr(),
            origin_len: origin.len(),
            origin: origin.as_ptr(),
            decoded: decoded.as_mut_ptr(),
        })
    }

    #[cfg(feature = "quic")]
    pub fn from_quic(packet: &QUICPacket, decoded: &mut [u8]) -> Self {
        TlsDecodeBuffer {
            suite: &CipherSuite::TLS_AES_128_GCM_SHA256,
            quic: true,
            head_len: packet.hdr_len(),
            head: packet.hdr_raw().as_ptr(),
            origin_len: packet.payload.len(),
            origin: packet.payload.as_ref().as_ptr(),
            decoded: decoded.as_mut_ptr(),
        }
    }

    pub fn aad(&self, seq: u64) -> RlsResult<Vec<u8>> {
        if self.quic { return Ok(unsafe { slice::from_raw_parts(self.head, self.head_len) }.to_vec()); }
        match *self.suite.version {
            Version::TLS_1_3 => Ok(self.tls13_aad()),
            Version::TLS_1_2 | Version::TLCP => Ok(self.tls12_aad(seq)),
            _ => Err("Unsupported version".into()),
        }
    }

    ///tls1.2 aad: seq||head[0..3]||pd_len(not tag)
    fn tls12_aad(&self, seq: u64) -> Vec<u8> {
        let mut res = vec![0; 13];
        res[0..8].copy_from_slice(seq.to_be_bytes().as_ref());
        res[8..11].copy_from_slice(unsafe { slice::from_raw_parts(self.head, 3) });
        let payload_len = self.origin_len as u16 - self.suite.trans_iv_len as u16 - 16;
        res[11..13].copy_from_slice(&payload_len.to_be_bytes());
        res
    }

    ///tls1.3 aad: head[0..3]||pd_len(tag)
    fn tls13_aad(&self) -> Vec<u8> {
        let mut res = vec![0; 5];
        res[0..3].copy_from_slice(unsafe { slice::from_raw_parts(self.head, 3) });
        let payload_len = self.origin_len as u16;
        res[3..5].copy_from_slice(&payload_len.to_be_bytes());
        res
    }

    pub fn encrypted_payload(&self) -> &[u8] {
        let len = self.origin_len - self.suite.trans_iv_len;
        unsafe { slice::from_raw_parts(self.origin.add(self.suite.trans_iv_len), len) }
    }

    pub fn explicit_iv(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.origin, self.suite.trans_iv_len) }
    }

    pub fn decrypted_buffer(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.decoded, self.origin_len - self.suite.trans_iv_len) }
    }

    pub fn head(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.head, self.head_len) }
    }

    pub fn nonce(&self, iv: &Iv, seq: u64) -> Vec<u8> {
        match self.suite.cipher() {
            CipherType::AES_128_GCM | CipherType::AES_256_GCM => match *self.suite.version {
                Version::TLS_1_3 => iv.as_array(seq, None).into_owned(),
                _ => iv.decrypting_iv(Some(self.explicit_iv())).into_owned()
            },
            CipherType::CHACHA20_POLY1305 => iv.as_array(seq, None).into_owned(),
            CipherType::AES_128_CBC |
            CipherType::AES_256_CBC |
            CipherType::SM4_CBC => iv.decrypting_iv(Some(self.explicit_iv())).into_owned(),
            _ => panic!("gen iv failed"),
        }
    }
}

