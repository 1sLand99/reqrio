use super::super::extend::Aead;
use crate::boring::{Hasher, Sha};
use crate::error::RlsResult;
use crate::RlsError;
use std::fmt::{Debug, Formatter};

pub struct CipherSuite {
    kind: u16,
    hasher: Option<Hasher>,
    aead: Option<Aead>,
}

impl CipherSuite {
    pub fn new(v: u16) -> CipherSuite {
        CipherSuite {
            kind: v,
            hasher: None,
            aead: None,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> RlsResult<Vec<CipherSuite>> {
        let mut res = vec![];
        for chuck in bytes.chunks(2) {
            let v = u16::from_be_bytes(chuck.try_into()?);
            res.push(CipherSuite::new(v));
        }
        Ok(res)
    }

    pub fn is_reserved(&self) -> bool {
        CipherSuiteKind::from_u16(self.kind).is_none()
    }

    pub fn as_bytes(&self) -> [u8; 2] {
        self.kind.to_be_bytes()
    }

    pub fn as_u16(&self) -> u16 {
        self.kind
    }

    pub fn update(&mut self, data: impl AsRef<[u8]>) -> RlsResult<()> {
        match self.hasher.as_mut() {
            None => Err(RlsError::HasherNone),
            Some(hasher) => hasher.update(data),
        }
    }

    fn find_hasher(&self, suite: &CipherSuiteKind) -> RlsResult<Hasher> {
        let text = format!("{:?}", suite).to_lowercase();
        if text.contains("sha256") {
            Ok(Hasher::new(Sha::Sha256)?)
        } else if text.contains("sha384") {
            Ok(Hasher::new(Sha::Sha384)?)
        } else if text.ends_with("_sha") {
            Ok(Hasher::new(Sha::Sha1)?)
        } else {
            Err(RlsError::HasherNone)
        }
    }

    pub fn current_session_hash(&mut self) -> RlsResult<&[u8]> {
        self.hasher.as_mut().ok_or(RlsError::HasherNone)?.current_hash()
    }

    pub fn aead(&self) -> Option<&Aead> {
        self.aead.as_ref()
    }

    pub fn init_aead_hasher(&mut self) -> RlsResult<()> {
        let kind = CipherSuiteKind::from_u16(self.kind).ok_or(RlsError::InvalidCipherSuite)?;
        //当hasher为空时需要把这个错误抛出，初始化hasher后一定不能为空
        self.hasher = Some(self.find_hasher(&kind)?);
        //aead同理
        self.aead = Some(Aead::from_cipher_kind(kind).ok_or(RlsError::AeadNone)?);
        Ok(())
    }

    pub fn hasher(&self) -> &Option<Hasher> {
        &self.hasher
    }
}

impl Debug for CipherSuite {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match CipherSuiteKind::from_u16(self.kind) {
            None => f.write_str(&format!("Reserved({})", self.kind)),
            Some(kind) => f.write_str(&format!("{:?}", kind))
        }
    }
}

impl PartialEq for CipherSuite {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind
    }
}


#[allow(non_camel_case_types)]
#[derive(Debug, Clone)]
pub enum CipherSuiteKind {
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xc02c,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xc030,
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = 0x009f,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca9,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca8,
    TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xccaa,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xc02b,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xc02f,
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = 0x009e,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = 0xc024,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = 0xc028,
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = 0x006b,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 0xc023,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = 0xc027,
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = 0x0067,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0xc00a,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xc014,
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA = 0x0039,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0xc009,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xc013,
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA = 0x0033,
    TLS_RSA_WITH_AES_256_GCM_SHA384 = 0x009d,
    TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009c,
    TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x003d,
    TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x003c,
    TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035,
    TLS_RSA_WITH_AES_128_CBC_SHA = 0x002f,
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00ff,
    TLS_AES_128_GCM_SHA256 = 0x1301,
    TLS_AES_256_GCM_SHA384 = 0x1302,
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303,

}

impl CipherSuiteKind {
    pub fn from_u16(byte: u16) -> Option<CipherSuiteKind> {
        match byte {
            0xc02c => Some(CipherSuiteKind::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384),
            0xc030 => Some(CipherSuiteKind::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384),
            0x009f => Some(CipherSuiteKind::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384),
            0xcca9 => Some(CipherSuiteKind::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256),
            0xcca8 => Some(CipherSuiteKind::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256),
            0xccaa => Some(CipherSuiteKind::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256),
            0xc02b => Some(CipherSuiteKind::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
            0xc02f => Some(CipherSuiteKind::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
            0x009e => Some(CipherSuiteKind::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256),
            0xc024 => Some(CipherSuiteKind::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384),
            0xc028 => Some(CipherSuiteKind::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384),
            0x006b => Some(CipherSuiteKind::TLS_DHE_RSA_WITH_AES_256_CBC_SHA256),
            0xc023 => Some(CipherSuiteKind::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256),
            0xc027 => Some(CipherSuiteKind::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256),
            0x0067 => Some(CipherSuiteKind::TLS_DHE_RSA_WITH_AES_128_CBC_SHA256),
            0xc00a => Some(CipherSuiteKind::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA),
            0xc014 => Some(CipherSuiteKind::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA),
            0x0039 => Some(CipherSuiteKind::TLS_DHE_RSA_WITH_AES_256_CBC_SHA),
            0xc009 => Some(CipherSuiteKind::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA),
            0xc013 => Some(CipherSuiteKind::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA),
            0x0033 => Some(CipherSuiteKind::TLS_DHE_RSA_WITH_AES_128_CBC_SHA),
            0x009d => Some(CipherSuiteKind::TLS_RSA_WITH_AES_256_GCM_SHA384),
            0x009c => Some(CipherSuiteKind::TLS_RSA_WITH_AES_128_GCM_SHA256),
            0x003d => Some(CipherSuiteKind::TLS_RSA_WITH_AES_256_CBC_SHA256),
            0x003c => Some(CipherSuiteKind::TLS_RSA_WITH_AES_128_CBC_SHA256),
            0x0035 => Some(CipherSuiteKind::TLS_RSA_WITH_AES_256_CBC_SHA),
            0x002f => Some(CipherSuiteKind::TLS_RSA_WITH_AES_128_CBC_SHA),
            0x00ff => Some(CipherSuiteKind::TLS_EMPTY_RENEGOTIATION_INFO_SCSV),
            0x1301 => Some(CipherSuiteKind::TLS_AES_128_GCM_SHA256),
            0x1302 => Some(CipherSuiteKind::TLS_AES_256_GCM_SHA384),
            0x1303 => Some(CipherSuiteKind::TLS_CHACHA20_POLY1305_SHA256),

            _ => None
        }
    }

    pub fn all() -> Vec<CipherSuiteKind> {
        vec![
            CipherSuiteKind::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            CipherSuiteKind::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuiteKind::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuiteKind::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuiteKind::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuiteKind::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuiteKind::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            CipherSuiteKind::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuiteKind::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuiteKind::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
            CipherSuiteKind::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
            CipherSuiteKind::TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
            CipherSuiteKind::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
            CipherSuiteKind::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
            CipherSuiteKind::TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
            CipherSuiteKind::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
            CipherSuiteKind::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            CipherSuiteKind::TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
            CipherSuiteKind::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            CipherSuiteKind::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            CipherSuiteKind::TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
            CipherSuiteKind::TLS_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuiteKind::TLS_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuiteKind::TLS_RSA_WITH_AES_256_CBC_SHA256,
            CipherSuiteKind::TLS_RSA_WITH_AES_128_CBC_SHA256,
            // CipherSuiteKind::TLS_RSA_WITH_AES_256_CBC_SHA,
            // CipherSuiteKind::TLS_RSA_WITH_AES_128_CBC_SHA,
            CipherSuiteKind::TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
            CipherSuiteKind::TLS_AES_128_GCM_SHA256,
            CipherSuiteKind::TLS_AES_256_GCM_SHA384,
            CipherSuiteKind::TLS_CHACHA20_POLY1305_SHA256,
        ]
    }
}


#[cfg(test)]
mod tests {
    use crate::boring::Sha;
    use crate::cipher::suite::Hasher;
    use std::fs;

    #[test]
    fn test_hasher() {
        let mut hasher = Hasher::new(Sha::Sha256).unwrap();
        hasher.update(fs::read("../ClientHello").unwrap()).unwrap();
        hasher.update(fs::read("../ServerHello").unwrap()).unwrap();
        hasher.update(fs::read("../Certificate").unwrap()).unwrap();
        hasher.update(fs::read("../ServerKeyExchange").unwrap()).unwrap();
        hasher.update(fs::read("../ServerHelloDone").unwrap()).unwrap();
        hasher.update(fs::read("../ClientKeyExchange").unwrap()).unwrap();
        let res = hasher.finalize().unwrap();
        println!("{:?}", res);
    }
}