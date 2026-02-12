use super::HandshakeType;
use std::fmt::Debug;
use crate::bytes::ByteRef;
use crate::error::RlsResult;
use super::super::bytes::Bytes;

#[derive(Debug)]
pub struct Certificates<'a> {
    handshake_type: HandshakeType,
    len: u32,
    certificate_len: u32,
    certificates: Vec<ByteRef<'a>>,
}

impl<'a> Default for Certificates<'a> {
    fn default() -> Self {
        Certificates {
            handshake_type: HandshakeType::Certificate,
            len: 0,
            certificate_len: 0,
            certificates: vec![],
        }
    }
}

impl<'a> Certificates<'a> {
    pub fn from_bytes(ht: HandshakeType, bytes: &[u8]) -> RlsResult<Certificates<'_>> {
        let mut res = Certificates::default();
        res.handshake_type = ht;
        res.len = u32::from_be_bytes([0, bytes[1], bytes[2], bytes[3]]);
        res.certificate_len = u32::from_be_bytes([0, bytes[4], bytes[5], bytes[6]]);
        let mut index = 7;
        while index < res.certificate_len as usize + 7 {
            let len = u32::from_be_bytes([0, bytes[index], bytes[index + 1], bytes[index + 2]]) as usize;
            index += 3;
            res.certificates.push(ByteRef::new(&bytes[index..index + len]));
            index += len
        }
        Ok(res)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut res = vec![self.handshake_type as u8, 0, 0, 0, 0, 0, 0];
        // res.extend_from_slice(&(self.len as u32).to_be_bytes()[1..]);
        // res.extend_from_slice(&(self.certificate_len as u32).to_be_bytes()[1..]);
        for certificate in &self.certificates {
            res.extend_from_slice(&(certificate.len() as u32).to_be_bytes()[1..]);
            res.extend_from_slice(certificate.as_ref())
        };
        let len = (res.len() - 4) as u32;
        res[1..4].copy_from_slice(len.to_be_bytes()[1..].as_ref());
        let len = (res.len() - 7) as u32;
        res[4..7].copy_from_slice(len.to_be_bytes()[1..].as_ref());
        res
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn len(&self) -> u32 {
        self.len
    }

    pub fn add_certificate(&mut self, cert: &'a [u8]) {
        self.certificates.push(ByteRef::new(cert));
    }

    pub fn certificates(&self) -> &Vec<ByteRef<'_>> {
        &self.certificates
    }
}

#[derive(Debug)]
pub struct CertificateStatus {
    // handshake_type: HandshakeType,
    bytes: Bytes,
}

impl CertificateStatus {
    pub fn from_bytes(_ht: HandshakeType, bytes: &[u8]) -> CertificateStatus {
        CertificateStatus {
            // handshake_type:ht,
            bytes: Bytes::new(bytes.to_vec()),
        }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        self.bytes.as_bytes()
    }

    pub fn len(&self) -> u32 {
        (self.bytes.len() - 4) as u32
    }
}