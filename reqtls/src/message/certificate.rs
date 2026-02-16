use super::HandshakeType;
use std::fmt::Debug;
use crate::bytes::ByteRef;
use crate::error::RlsResult;
use crate::WriteExt;
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

    pub fn len(&self) -> usize {
        7 + self.certificates.iter().map(|x| 3 + x.len()).sum::<usize>()
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) {
        writer.write_u8(self.handshake_type as u8);
        writer.write_slice(&(self.len() as u32 - 4).to_be_bytes()[1..]);
        writer.write_slice(&(self.len() as u32 - 7).to_be_bytes()[1..]);
        for certificate in self.certificates {
            writer.write_slice(&(certificate.len() as u32).to_be_bytes()[1..]);
            writer.write_slice(certificate.as_ref());
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
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

    pub fn len(&self) -> usize { self.bytes.len() }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) {
        writer.write_slice(self.bytes.as_ref())
    }
}