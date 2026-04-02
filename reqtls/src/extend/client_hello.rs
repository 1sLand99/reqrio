use super::super::bytes::Bytes;
use crate::error::RlsResult;
use crate::{BufferError, WriteExt};

#[derive(Debug, Clone, Copy)]
enum ClientHelloType {
    OuterClientHello = 0,
}

impl ClientHelloType {
    fn from_u8(v: u8) -> Option<ClientHelloType> {
        match v {
            0 => Some(ClientHelloType::OuterClientHello),
            _ => None
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[allow(non_camel_case_types)]
enum KDF {
    HKDF_SHA256 = 0x1,
}

impl KDF {
    fn from_u16(v: u16) -> Option<KDF> {
        match v {
            0x01 => Some(KDF::HKDF_SHA256),
            _ => None
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[allow(non_camel_case_types)]
pub enum Aead {
    AES_128_GCM = 0x1,
    AES_256_GCM = 0x2,
    ChaCha20_POLY1305 = 0x3,
    AES_128_CCM = 0x4,
    AES_128_CCM_8 = 0x5,
    AES_128_CBC_SHA,
    AES_256_CBC_SHA,
}

impl Aead {
    fn from_u16(v: u16) -> Option<Aead> {
        match v {
            0x01 => Some(Aead::AES_128_GCM),
            0x02 => Some(Aead::AES_256_GCM),
            0x03 => Some(Aead::ChaCha20_POLY1305),
            0x04 => Some(Aead::AES_128_CCM),
            0x05 => Some(Aead::AES_128_CCM_8),
            _ => None
        }
    }

    pub fn from_cipher_kind(suite_spec: &str) -> Option<Aead> {
        let text = suite_spec.to_lowercase();
        if text.contains("aes_128_gcm") {
            Some(Aead::AES_128_GCM)
        } else if text.contains("aes_256_gcm") {
            Some(Aead::AES_256_GCM)
        } else if text.contains("chacha20_poly1305") {
            Some(Aead::ChaCha20_POLY1305)
        } else if text.contains("aes_128_cbc") {
            Some(Aead::AES_128_CBC_SHA)
        } else if text.contains("aes_256_cbc") {
            Some(Aead::AES_256_CBC_SHA)
        } else {
            println!("{}", text);
            None
        }
    }

    pub fn mac_key_len(&self) -> usize {
        match self {
            Aead::AES_128_CBC_SHA | Aead::AES_256_CBC_SHA => 20,
            _ => 0
        }
    }

    pub fn key_len(&self) -> usize {
        match self {
            Aead::AES_128_GCM => 16,
            Aead::AES_256_GCM => 32,
            Aead::ChaCha20_POLY1305 => 32,
            Aead::AES_128_CBC_SHA => 16,
            Aead::AES_256_CBC_SHA => 32,
            _ => 0
        }
    }

    pub fn fix_iv_len(&self) -> usize {
        match self {
            Aead::AES_128_GCM | Aead::AES_256_GCM => 4,
            Aead::ChaCha20_POLY1305 => 12,
            Aead::AES_128_CBC_SHA | Aead::AES_256_CBC_SHA => 16,
            _ => 0
        }
    }

    pub fn explicit_len(&self) -> usize {
        match self {
            Aead::AES_128_GCM | Aead::AES_256_GCM => 8,
            Aead::ChaCha20_POLY1305 => 0,
            Aead::AES_128_CBC_SHA | Aead::AES_256_CBC_SHA => 16,
            _ => 0
        }
    }
}


#[derive(Debug)]
struct CipherSuite {
    kdf: KDF,
    aead: Aead,
}

impl CipherSuite {
    pub fn from_bytes(bytes: &[u8]) -> RlsResult<CipherSuite> {
        Ok(CipherSuite {
            kdf: KDF::from_u16(u16::from_be_bytes([bytes[0], bytes[1]])).ok_or("KDF Unknown")?,
            aead: Aead::from_u16(u16::from_be_bytes([bytes[2], bytes[3]])).ok_or("AEAD Unknown")?,
        })
    }

    pub fn len(&self) -> usize { 4 }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) -> Result<(), BufferError> {
        writer.write_u16(self.kdf as u16)?;
        writer.write_u16(self.aead as u16)
    }
}


#[derive(Debug)]
pub struct EncryptClientHello {
    type_: ClientHelloType,
    cipher_suite: CipherSuite,
    config_id: u8,
    enc_len: u16,
    enc: Bytes,
    payload_len: u16,
    payload: Bytes,
}

impl EncryptClientHello {
    pub fn new() -> EncryptClientHello {
        EncryptClientHello {
            type_: ClientHelloType::OuterClientHello,
            cipher_suite: CipherSuite {
                kdf: KDF::HKDF_SHA256,
                aead: Aead::AES_128_GCM,
            },
            config_id: 0,
            enc_len: 0,
            enc: Bytes::none(),
            payload_len: 0,
            payload: Bytes::none(),
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> RlsResult<EncryptClientHello> {
        let mut res = EncryptClientHello::new();
        res.type_ = ClientHelloType::from_u8(bytes[0]).ok_or("ClientHelloType Unknown")?;
        res.cipher_suite = CipherSuite::from_bytes(&bytes[1..])?;
        res.config_id = bytes[5];
        res.enc_len = u16::from_be_bytes([bytes[6], bytes[7]]);
        res.enc = Bytes::new(bytes[8..8 + res.enc_len as usize].to_vec());
        let index = res.enc_len as usize + 8;
        res.payload_len = u16::from_be_bytes([bytes[index], bytes[index + 1]]);
        res.payload = Bytes::new(bytes[index + 2..index + res.payload_len as usize + 2].to_vec());
        Ok(res)
    }

    pub fn len(&self) -> usize {
        6 + self.cipher_suite.len() + self.enc.len() + self.payload.len()
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) -> Result<(), BufferError> {
        writer.write_u8(self.type_ as u8)?;
        self.cipher_suite.write_to(writer)?;
        writer.write_u8(self.config_id)?;
        writer.write_u16(self.enc.len() as u16)?;
        writer.write_slice(self.enc.as_ref())?;
        writer.write_u16(self.payload.len() as u16)?;
        writer.write_slice(self.payload.as_ref())
    }
}