use super::super::extend::Aead;
use crate::boring::{Hasher, Sha};
use crate::error::RlsResult;
use crate::RlsError;
use std::fmt::{Debug, Formatter};

pub struct CipherSuite {
    value: u16,
    hasher: Option<Hasher>,
    aead: Option<Aead>,
}

impl CipherSuite {
    //ecdhe-ecdhe
    pub const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: CipherSuite = CipherSuite {
        value: 0xc02b,
        hasher: None,
        aead: None,
    };
    pub const TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: CipherSuite = CipherSuite {
        value: 0xc02c,
        hasher: None,
        aead: None,
    };
    pub const TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: CipherSuite = CipherSuite {
        value: 0xc023,
        hasher: None,
        aead: None,
    };
    pub const TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384: CipherSuite = CipherSuite {
        value: 0xc024,
        hasher: None,
        aead: None,
    };
    pub const TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: CipherSuite = CipherSuite {
        value: 0xc009,
        hasher: None,
        aead: None,
    };
    pub const TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: CipherSuite = CipherSuite {
        value: 0xc00a,
        hasher: None,
        aead: None,
    };
    pub const TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: CipherSuite = CipherSuite {
        value: 0xcca9,
        hasher: None,
        aead: None,
    };

    //ecdhe-rsa
    pub const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: CipherSuite = CipherSuite {
        value: 0xc02f,
        hasher: None,
        aead: None,
    };
    pub const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: CipherSuite = CipherSuite {
        value: 0xc030,
        hasher: None,
        aead: None,
    };
    pub const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256: CipherSuite = CipherSuite {
        value: 0xc027,
        hasher: None,
        aead: None,
    };
    pub const TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384: CipherSuite = CipherSuite {
        value: 0xc028,
        hasher: None,
        aead: None,
    };
    pub const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: CipherSuite = CipherSuite {
        value: 0xc013,
        hasher: None,
        aead: None,
    };
    pub const TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: CipherSuite = CipherSuite {
        value: 0xc014,
        hasher: None,
        aead: None,
    };
    pub const TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: CipherSuite = CipherSuite {
        value: 0xcca8,
        hasher: None,
        aead: None,
    };

    //dhe-rsa
    pub const TLS_DHE_RSA_WITH_AES_128_GCM_SHA256: CipherSuite = CipherSuite {
        value: 0x009e,
        hasher: None,
        aead: None,
    };
    pub const TLS_DHE_RSA_WITH_AES_256_GCM_SHA384: CipherSuite = CipherSuite {
        value: 0x009f,
        hasher: None,
        aead: None,
    };
    pub const TLS_DHE_RSA_WITH_AES_128_CBC_SHA256: CipherSuite = CipherSuite {
        value: 0x0067,
        hasher: None,
        aead: None,
    };
    pub const TLS_DHE_RSA_WITH_AES_256_CBC_SHA256: CipherSuite = CipherSuite {
        value: 0x006b,
        hasher: None,
        aead: None,
    };
    pub const TLS_DHE_RSA_WITH_AES_128_CBC_SHA: CipherSuite = CipherSuite {
        value: 0x0033,
        hasher: None,
        aead: None,
    };
    pub const TLS_DHE_RSA_WITH_AES_256_CBC_SHA: CipherSuite = CipherSuite {
        value: 0x0039,
        hasher: None,
        aead: None,
    };
    pub const TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256: CipherSuite = CipherSuite {
        value: 0xccaa,
        hasher: None,
        aead: None,
    };


    //rsa
    pub const TLS_RSA_WITH_AES_128_GCM_SHA256: CipherSuite = CipherSuite {
        value: 0x009c,
        hasher: None,
        aead: None,
    };
    pub const TLS_RSA_WITH_AES_256_GCM_SHA384: CipherSuite = CipherSuite {
        value: 0x009d,
        hasher: None,
        aead: None,
    };
    pub const TLS_RSA_WITH_AES_128_CBC_SHA256: CipherSuite = CipherSuite {
        value: 0x003c,
        hasher: None,
        aead: None,
    };
    pub const TLS_RSA_WITH_AES_256_CBC_SHA256: CipherSuite = CipherSuite {
        value: 0x003d,
        hasher: None,
        aead: None,
    };
    pub const TLS_RSA_WITH_AES_128_CBC_SHA: CipherSuite = CipherSuite {
        value: 0x002f,
        hasher: None,
        aead: None,
    };
    pub const TLS_RSA_WITH_AES_256_CBC_SHA: CipherSuite = CipherSuite {
        value: 0x0035,
        hasher: None,
        aead: None,
    };

    //empty
    pub const TLS_AES_128_GCM_SHA256: CipherSuite = CipherSuite {
        value: 0x1301,
        hasher: None,
        aead: None,
    };
    pub const TLS_AES_256_GCM_SHA384: CipherSuite = CipherSuite {
        value: 0x1302,
        hasher: None,
        aead: None,
    };
    pub const TLS_CHACHA20_POLY1305_SHA256: CipherSuite = CipherSuite {
        value: 0x1303,
        hasher: None,
        aead: None,
    };

    pub const TLS_EMPTY_RENEGOTIATION_INFO_SCSV: CipherSuite = CipherSuite {
        value: 0x00ff,
        hasher: None,
        aead: None,
    };

    pub const SUITES: [u16; 31] = [0xc02b, 0xc02c, 0xc023, 0xc024, 0xc009, 0xc00a, 0xcca9, 0xc02f, 0xc030, 0xc027, 0xc028, 0xc013, 0xc014, 0xcca8, 0x009e, 0x009f, 0x0067, 0x006b, 0x0033, 0x0039, 0xccaa, 0x009c, 0x009d, 0x003c, 0x003d, 0x002f, 0x0035, 0x1301, 0x1302, 0x1303, 0x00ff];

    pub fn spec(&self) -> &str {
        match self.value {
            0xc02b => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            0xc02c => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            0xc023 => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
            0xc024 => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
            0xc009 => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
            0xc00a => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
            0xcca9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",

            0xc02f => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            0xc030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            0xc027 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
            0xc028 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
            0xc013 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            0xc014 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            0xcca8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",

            0x009e => "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
            0x009f => "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
            0x0067 => "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
            0x006b => "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
            0x0033 => "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
            0x0039 => "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
            0xccaa => "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",

            0x009c => "TLS_RSA_WITH_AES_128_GCM_SHA256",
            0x009d => "TLS_RSA_WITH_AES_256_GCM_SHA384",
            0x003c => "TLS_RSA_WITH_AES_128_CBC_SHA256",
            0x003d => "TLS_RSA_WITH_AES_256_CBC_SHA256",
            0x002f => "TLS_RSA_WITH_AES_128_CBC_SHA",
            0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA",

            0x1301 => "TLS_AES_128_GCM_SHA256",
            0x1302 => "TLS_AES_256_GCM_SHA384",
            0x1303 => "TLS_CHACHA20_POLY1305_SHA256",

            0x00ff => "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
            _ => "Reserved"
        }
    }

    pub fn key_size(&self) -> u8 {
        match self.value {
            0x009c | 0x009d | 0x003c | 0x003d | 0x002f | 0x0035 => 2,
            _ => 1,
        }
    }
}

impl PartialEq for CipherSuite {
    fn eq(&self, other: &CipherSuite) -> bool {
        self.value == other.value
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
        !CipherSuite::SUITES.contains(&self.value)
    }

    pub fn as_bytes(&self) -> [u8; 2] {
        self.value.to_be_bytes()
    }

    pub fn as_u16(&self) -> u16 {
        self.value
    }

    pub fn update(&mut self, data: impl AsRef<[u8]>) -> RlsResult<()> {
        match self.hasher.as_mut() {
            None => Err(RlsError::HasherNone),
            Some(hasher) => hasher.update(data),
        }
    }

    fn find_hasher(&self) -> RlsResult<Hasher> {
        let text = self.spec().to_lowercase();
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


// #[allow(non_camel_case_types)]
// #[derive(Debug, Clone)]
// pub enum CipherSuiteKind {
//     TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xc02b,
//     TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xc02c,
//     TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 0xc023,
//     TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = 0xc024,
//     TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0xc009,
//     TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0xc00a,
//     TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca9,
//
//     TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xc02f,
//     TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xc030,
//     TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = 0xc027,
//     TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = 0xc028,
//     TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xc013,
//     TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xc014,
//     TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca8,
//
//     TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = 0x009e,
//     TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = 0x009f,
//     TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = 0x0067,
//     TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = 0x006b,
//     TLS_DHE_RSA_WITH_AES_128_CBC_SHA = 0x0033,
//     TLS_DHE_RSA_WITH_AES_256_CBC_SHA = 0x0039,
//     TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xccaa,
//
//     TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009c,
//     TLS_RSA_WITH_AES_256_GCM_SHA384 = 0x009d,
//     TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x003c,
//     TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x003d,
//     TLS_RSA_WITH_AES_128_CBC_SHA = 0x002f,
//     TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035,
//
//     TLS_AES_128_GCM_SHA256 = 0x1301,
//     TLS_AES_256_GCM_SHA384 = 0x1302,
//     TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
//
//     TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00ff,
// }
//
// impl CipherSuiteKind {
//     pub fn from_u16(byte: u16) -> Option<CipherSuiteKind> {
//         match byte {
//             0xc02c => Some(CipherSuiteKind::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384),
//             0xc030 => Some(CipherSuiteKind::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384),
//             0x009f => Some(CipherSuiteKind::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384),
//             0xcca9 => Some(CipherSuiteKind::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256),
//             0xcca8 => Some(CipherSuiteKind::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256),
//             0xccaa => Some(CipherSuiteKind::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256),
//             0xc02b => Some(CipherSuiteKind::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
//             0xc02f => Some(CipherSuiteKind::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
//             0x009e => Some(CipherSuiteKind::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256),
//             0xc024 => Some(CipherSuiteKind::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384),
//             0xc028 => Some(CipherSuiteKind::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384),
//             0x006b => Some(CipherSuiteKind::TLS_DHE_RSA_WITH_AES_256_CBC_SHA256),
//             0xc023 => Some(CipherSuiteKind::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256),
//             0xc027 => Some(CipherSuiteKind::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256),
//             0x0067 => Some(CipherSuiteKind::TLS_DHE_RSA_WITH_AES_128_CBC_SHA256),
//             0xc00a => Some(CipherSuiteKind::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA),
//             0xc014 => Some(CipherSuiteKind::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA),
//             0x0039 => Some(CipherSuiteKind::TLS_DHE_RSA_WITH_AES_256_CBC_SHA),
//             0xc009 => Some(CipherSuiteKind::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA),
//             0xc013 => Some(CipherSuiteKind::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA),
//             0x0033 => Some(CipherSuiteKind::TLS_DHE_RSA_WITH_AES_128_CBC_SHA),
//             0x009d => Some(CipherSuiteKind::TLS_RSA_WITH_AES_256_GCM_SHA384),
//             0x009c => Some(CipherSuiteKind::TLS_RSA_WITH_AES_128_GCM_SHA256),
//             0x003d => Some(CipherSuiteKind::TLS_RSA_WITH_AES_256_CBC_SHA256),
//             0x003c => Some(CipherSuiteKind::TLS_RSA_WITH_AES_128_CBC_SHA256),
//             0x0035 => Some(CipherSuiteKind::TLS_RSA_WITH_AES_256_CBC_SHA),
//             0x002f => Some(CipherSuiteKind::TLS_RSA_WITH_AES_128_CBC_SHA),
//             0x00ff => Some(CipherSuiteKind::TLS_EMPTY_RENEGOTIATION_INFO_SCSV),
//             0x1301 => Some(CipherSuiteKind::TLS_AES_128_GCM_SHA256),
//             0x1302 => Some(CipherSuiteKind::TLS_AES_256_GCM_SHA384),
//             0x1303 => Some(CipherSuiteKind::TLS_CHACHA20_POLY1305_SHA256),
//
//             _ => None
//         }
//     }
//
//     pub fn all() -> Vec<CipherSuiteKind> {
//         vec![
//             CipherSuiteKind::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
//             CipherSuiteKind::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
//             CipherSuiteKind::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
//             CipherSuiteKind::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
//             CipherSuiteKind::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
//             CipherSuiteKind::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
//             CipherSuiteKind::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
//             CipherSuiteKind::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
//             CipherSuiteKind::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
//             CipherSuiteKind::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
//             CipherSuiteKind::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
//             CipherSuiteKind::TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
//             CipherSuiteKind::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
//             CipherSuiteKind::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
//             CipherSuiteKind::TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
//             CipherSuiteKind::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
//             CipherSuiteKind::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
//             CipherSuiteKind::TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
//             CipherSuiteKind::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
//             CipherSuiteKind::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
//             CipherSuiteKind::TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
//             CipherSuiteKind::TLS_RSA_WITH_AES_256_GCM_SHA384,
//             CipherSuiteKind::TLS_RSA_WITH_AES_128_GCM_SHA256,
//             CipherSuiteKind::TLS_RSA_WITH_AES_256_CBC_SHA256,
//             CipherSuiteKind::TLS_RSA_WITH_AES_128_CBC_SHA256,
//             // CipherSuiteKind::TLS_RSA_WITH_AES_256_CBC_SHA,
//             // CipherSuiteKind::TLS_RSA_WITH_AES_128_CBC_SHA,
//             CipherSuiteKind::TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
//             CipherSuiteKind::TLS_AES_128_GCM_SHA256,
//             CipherSuiteKind::TLS_AES_256_GCM_SHA384,
//             CipherSuiteKind::TLS_CHACHA20_POLY1305_SHA256,
//         ]
//     }
// }


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