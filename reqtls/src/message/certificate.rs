use super::super::bytes::Bytes;
use super::HandshakeType;
use crate::bytes::ByteRef;
use crate::error::RlsResult;
use crate::{BufferError, CertType, SignatureAlgorithm, WriteExt};
use std::fmt::Debug;

#[derive(Debug)]
pub struct Certificates<'a> {
    handshake_type: HandshakeType,
    certificate_len: u32,
    certificates: Vec<ByteRef<'a>>,
}

impl<'a> Default for Certificates<'a> {
    fn default() -> Self {
        Certificates {
            handshake_type: HandshakeType::Certificate,
            certificate_len: 0,
            certificates: vec![],
        }
    }
}

impl<'a> Certificates<'a> {
    pub fn from_bytes(ht: HandshakeType, bytes: &[u8]) -> RlsResult<Certificates<'_>> {
        let mut res = Certificates {
            handshake_type: ht,
            certificate_len: u32::from_be_bytes([0, bytes[4], bytes[5], bytes[6]]),
            ..Certificates::default()
        };
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

    pub fn write_to<W: WriteExt>(self, writer: &mut W) -> Result<(), BufferError> {
        writer.write_u8(self.handshake_type as u8)?;
        writer.write_u32(self.len() as u32 - 4, true)?;
        writer.write_u32(self.len() as u32 - 7, true)?;
        for certificate in self.certificates {
            writer.write_u32(certificate.len() as u32, true)?;
            writer.write_slice(certificate.as_ref())?;
        }
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
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

    pub fn write_to<W: WriteExt>(self, writer: &mut W) -> Result<(), BufferError> {
        writer.write_slice(self.bytes.as_ref())
    }
}


#[derive(Debug)]
pub struct CertificateRequest<'a> {
    handshake_type: HandshakeType,
    cert_type: Vec<CertType>,
    hashes: Vec<SignatureAlgorithm>,
    distinguished_name: ByteRef<'a>,
}

impl<'a> Default for CertificateRequest<'a> {
    fn default() -> Self {
        CertificateRequest {
            handshake_type: HandshakeType::CertificateRequest,
            cert_type: vec![],
            hashes: vec![],
            distinguished_name: Default::default(),
        }
    }
}

impl<'a> CertificateRequest<'a> {
    pub fn random() -> CertificateRequest<'a> {
        let mut res = CertificateRequest {
            cert_type: vec![CertType::RSA, CertType::ECDSA],
            hashes: vec![
                SignatureAlgorithm::RSA_PSS_PSS_SHA256,
                SignatureAlgorithm::RSA_PSS_PSS_SHA384,
                SignatureAlgorithm::RSA_PSS_PSS_SHA512,
            ],
            ..CertificateRequest::default()
        };
        for hash in SignatureAlgorithm::ALL {
            if res.hashes.len() >= 10 { break; }
            if res.hashes.contains(&SignatureAlgorithm::new(hash)) { continue; }
            res.hashes.push(SignatureAlgorithm::new(hash));
        }
        res
    }

    pub fn from_bytes(ht: HandshakeType, bytes: &'a [u8]) -> CertificateRequest<'a> {
        let mut res = CertificateRequest {
            handshake_type: ht,
            ..Default::default()
        };
        for count in 0..bytes[4] {
            res.cert_type.push(CertType::new(bytes[5 + count as usize]));
        }
        let mut index = 5 + bytes[4] as usize;
        let len = u16::from_be_bytes([bytes[index], bytes[index + 1]]) as usize;
        index += 2;
        for chunk in bytes[index..index + len].chunks(2) {
            let value = u16::from_be_bytes([chunk[0], chunk[1]]);
            res.hashes.push(SignatureAlgorithm::new(value));
        }
        index += len;
        let len = u16::from_be_bytes([bytes[index], bytes[index + 1]]) as usize;
        index += 2;
        res.distinguished_name = ByteRef::new(&bytes[index..index + len]);
        res
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn len(&self) -> usize {
        9 + self.cert_type.len() + self.hashes.len() * 2 + self.distinguished_name.len()
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) -> Result<(), BufferError> {
        writer.write_u8(self.handshake_type as u8)?;
        writer.write_u32(self.len() as u32 - 4, true)?;
        writer.write_u8(self.cert_type.len() as u8)?;
        writer.write_u16(self.hashes.len() as u16 * 2)?;
        for hash in self.hashes {
            writer.write_u16(hash.into_inner())?;
        }
        writer.write_u16(self.distinguished_name.len() as u16)?;
        writer.write_slice(self.distinguished_name.as_ref())
    }

    pub fn hashes(&self) -> &Vec<SignatureAlgorithm> {
        &self.hashes
    }

    pub fn into_hashes(self) -> Vec<SignatureAlgorithm> {
        self.hashes
    }
}

#[derive(Debug)]
pub struct CertificateVerify<'a> {
    handshake_type: HandshakeType,
    sign_hash: SignatureAlgorithm,
    sign: ByteRef<'a>,
}

impl<'a> Default for CertificateVerify<'a> {
    fn default() -> Self {
        CertificateVerify {
            handshake_type: HandshakeType::CertificateVerify,
            sign_hash: SignatureAlgorithm::RSA_PSS_RSAE_SHA256,
            sign: Default::default(),
        }
    }
}

impl<'a> CertificateVerify<'a> {
    pub fn from_bytes(ht: HandshakeType, bytes: &'a [u8]) -> CertificateVerify<'a> {
        let sign_len = u16::from_be_bytes([bytes[6], bytes[7]]);
        CertificateVerify {
            handshake_type: ht,
            sign_hash: SignatureAlgorithm::new(u16::from_be_bytes([bytes[4], bytes[5]])),
            sign: ByteRef::new(&bytes[8..8 + sign_len as usize]),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn len(&self) -> usize {
        8 + self.sign.len()
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) -> Result<(), BufferError> {
        writer.write_u8(self.handshake_type as u8)?;
        writer.write_u32(self.len() as u32 - 4, true)?;
        writer.write_u16(self.sign_hash.into_inner())?;
        writer.write_u16(self.sign.len() as u16)?;
        writer.write_slice(self.sign.as_ref())
    }

    pub fn set_hash(&mut self, hash: SignatureAlgorithm) {
        self.sign_hash = hash;
    }

    pub fn set_sign(&mut self, sign: &'a [u8]) {
        self.sign = ByteRef::new(sign);
    }
}