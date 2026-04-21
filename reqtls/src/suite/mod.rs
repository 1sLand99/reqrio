use crate::error::RlsResult;
use crate::extend::Aead;
use crate::hash::{HashError, HashType};
use crate::{Hasher, RlsError};
pub use cipher::TlsCipher;
use std::fmt::{Debug, Formatter};

pub mod iv;
mod cipher;

pub struct CipherSuite {
    value: u16,
    hasher: Option<Hasher>,
    aead: Option<Aead>,
}

impl CipherSuite {
    //ecdhe-ecdhe
    pub const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: u16 = 0xc02b;
    pub const TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: u16 = 0xc02c;
    pub const TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: u16 = 0xc023;
    pub const TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384: u16 = 0xc024;
    pub const TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: u16 = 0xc009;
    pub const TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: u16 = 0xc00a;
    pub const TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: u16 = 0xcca9;

    //ecdhe-rsa
    pub const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: u16 = 0xc02f;
    pub const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: u16 = 0xc030;
    pub const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256: u16 = 0xc027;
    pub const TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384: u16 = 0xc028;
    pub const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: u16 = 0xc013;
    pub const TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: u16 = 0xc014;
    pub const TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: u16 = 0xcca8;

    //dhe-rsa
    pub const TLS_DHE_RSA_WITH_AES_128_GCM_SHA256: u16 = 0x009e;
    pub const TLS_DHE_RSA_WITH_AES_256_GCM_SHA384: u16 = 0x009f;
    pub const TLS_DHE_RSA_WITH_AES_128_CBC_SHA256: u16 = 0x0067;
    pub const TLS_DHE_RSA_WITH_AES_256_CBC_SHA256: u16 = 0x006b;
    pub const TLS_DHE_RSA_WITH_AES_128_CBC_SHA: u16 = 0x0033;
    pub const TLS_DHE_RSA_WITH_AES_256_CBC_SHA: u16 = 0x0039;
    pub const TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256: u16 = 0xccaa;


    //rsa
    pub const TLS_RSA_WITH_AES_128_GCM_SHA256: u16 = 0x009c;
    pub const TLS_RSA_WITH_AES_256_GCM_SHA384: u16 = 0x009d;
    pub const TLS_RSA_WITH_AES_128_CBC_SHA256: u16 = 0x003c;
    pub const TLS_RSA_WITH_AES_256_CBC_SHA256: u16 = 0x003d;
    pub const TLS_RSA_WITH_AES_128_CBC_SHA: u16 = 0x002f;
    pub const TLS_RSA_WITH_AES_256_CBC_SHA: u16 = 0x0035;

    //tls1.3
    pub const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
    pub const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
    pub const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

    pub const TLS_EMPTY_RENEGOTIATION_INFO_SCSV: u16 = 0x00ff;

    pub const ALL: [u16; 31] = [
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,

        //ecdhe-rsa
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,

        //dhe-rsa
        CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
        CipherSuite::TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
        CipherSuite::TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
        CipherSuite::TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
        CipherSuite::TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
        CipherSuite::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,


        //rsa
        CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384,
        CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA256,
        CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA256,
        CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
        CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA,

        //empty
        CipherSuite::TLS_AES_128_GCM_SHA256,
        CipherSuite::TLS_AES_256_GCM_SHA384,
        CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
        CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
    ];

    pub fn spec(&self) -> &str {
        match self.value {
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
            CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",

            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",

            CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 => "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
            CipherSuite::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 => "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
            CipherSuite::TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 => "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
            CipherSuite::TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 => "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
            CipherSuite::TLS_DHE_RSA_WITH_AES_128_CBC_SHA => "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
            CipherSuite::TLS_DHE_RSA_WITH_AES_256_CBC_SHA => "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
            CipherSuite::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",

            CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256 => "TLS_RSA_WITH_AES_128_GCM_SHA256",
            CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384 => "TLS_RSA_WITH_AES_256_GCM_SHA384",
            CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA256 => "TLS_RSA_WITH_AES_128_CBC_SHA256",
            CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA256 => "TLS_RSA_WITH_AES_256_CBC_SHA256",
            CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA => "TLS_RSA_WITH_AES_128_CBC_SHA",
            CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA => "TLS_RSA_WITH_AES_256_CBC_SHA",

            CipherSuite::TLS_AES_128_GCM_SHA256 => "TLS_AES_128_GCM_SHA256",
            CipherSuite::TLS_AES_256_GCM_SHA384 => "TLS_AES_256_GCM_SHA384",
            CipherSuite::TLS_CHACHA20_POLY1305_SHA256 => "TLS_CHACHA20_POLY1305_SHA256",

            CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV => "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
            _ => "Reserved"
        }
    }

    pub fn key_size(&self) -> u8 {
        match self.value {
            CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256 | CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384 |
            CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA256 | CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA256 |
            CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA | CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA => 2,
            _ => 1,
        }
    }

    pub fn is_aead(&self) -> bool {
        matches!(self.value, CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 |
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 |
            CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 |
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 |
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 |
            CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 |
            CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 |
            CipherSuite::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 |
            CipherSuite::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 |
            CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256 |
            CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384 |
            CipherSuite::TLS_AES_128_GCM_SHA256 |
            CipherSuite::TLS_AES_256_GCM_SHA384 |
            CipherSuite::TLS_CHACHA20_POLY1305_SHA256)
    }


    pub fn mac_hash(&self) -> Option<HashType> {
        match self.value {
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => Some(HashType::Sha256),
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => Some(HashType::Sha384),
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 => Some(HashType::Sha256),
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 => Some(HashType::Sha384),
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA => Some(HashType::Sha1),
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA => Some(HashType::Sha1),
            CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => Some(HashType::Sha256),

            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => Some(HashType::Sha256),
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => Some(HashType::Sha384),
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 => Some(HashType::Sha256),
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 => Some(HashType::Sha384),
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA => Some(HashType::Sha1),
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA => Some(HashType::Sha1),
            CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => Some(HashType::Sha256),

            CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 => Some(HashType::Sha256),
            CipherSuite::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 => Some(HashType::Sha384),

            CipherSuite::TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 => Some(HashType::Sha256),
            CipherSuite::TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 => Some(HashType::Sha256),
            CipherSuite::TLS_DHE_RSA_WITH_AES_128_CBC_SHA => Some(HashType::Sha1),
            CipherSuite::TLS_DHE_RSA_WITH_AES_256_CBC_SHA => Some(HashType::Sha1),
            CipherSuite::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => Some(HashType::Sha256),

            CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256 => Some(HashType::Sha256),
            CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384 => Some(HashType::Sha384),
            CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA256 => Some(HashType::Sha256),
            CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA256 => Some(HashType::Sha256),
            CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA => Some(HashType::Sha1),
            CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA => Some(HashType::Sha1),

            CipherSuite::TLS_AES_128_GCM_SHA256 => Some(HashType::Sha256),
            CipherSuite::TLS_AES_256_GCM_SHA384 => Some(HashType::Sha384),
            CipherSuite::TLS_CHACHA20_POLY1305_SHA256 => Some(HashType::Sha256),
            _ => None
        }
    }
}

impl From<u16> for CipherSuite {
    fn from(value: u16) -> Self {
        CipherSuite::new(value)
    }
}

impl From<&u16> for CipherSuite {
    fn from(value: &u16) -> Self {
        CipherSuite::new(*value)
    }
}

impl PartialEq for CipherSuite {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl PartialEq<u16> for CipherSuite {
    fn eq(&self, other: &u16) -> bool {
        self.value == *other
    }
}

impl PartialEq<u16> for &CipherSuite {
    fn eq(&self, other: &u16) -> bool {
        self.value == *other
    }
}

impl Clone for CipherSuite {
    fn clone(&self) -> Self {
        CipherSuite::new(self.value)
    }
}

impl CipherSuite {
    pub fn new(v: u16) -> CipherSuite {
        CipherSuite {
            value: v,
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
        !CipherSuite::ALL.contains(&self.value)
    }

    pub fn into_inner(self) -> u16 { self.value }

    pub fn as_u16(&self) -> u16 {
        self.value
    }

    pub fn update(&mut self, data: impl AsRef<[u8]>) -> Result<(), HashError> {
        match self.hasher.as_mut() {
            None => Err(HashError::HasherNone),
            Some(hasher) => hasher.update(data),
        }
    }

    fn find_hasher(&self) -> Result<Hasher, HashError> {
        let text = self.spec().to_lowercase();
        if text.contains("sha256") {
            Ok(Hasher::new(HashType::Sha256)?)
        } else if text.contains("sha384") {
            Ok(Hasher::new(HashType::Sha384)?)
        } else if text.ends_with("_sha") {
            Ok(Hasher::new(HashType::Sha256)?)
        } else {
            Err(HashError::UnsupportedHasher(text))
        }
    }

    pub fn current_session_hash(&mut self) -> Result<&[u8], HashError> {
        self.hasher.as_mut().ok_or(HashError::HasherNone)?.current_hash()
    }

    pub fn aead(&self) -> Option<&Aead> {
        self.aead.as_ref()
    }

    pub fn init_aead_hasher(&mut self) -> RlsResult<()> {
        //当hasher为空时需要把这个错误抛出，初始化hasher后一定不能为空
        self.hasher = Some(self.find_hasher()?);
        //aead同理
        self.aead = Some(Aead::from_cipher_kind(self.spec()).ok_or(RlsError::AeadNone)?);
        Ok(())
    }

    pub fn hasher(&self) -> &Option<Hasher> {
        &self.hasher
    }
}

impl Debug for CipherSuite {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}(0x{:x})", self.spec(), self.value)
    }
}