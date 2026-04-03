use std::error::Error;
use std::fmt::Display;

#[derive(Debug)]
pub enum HashError {
    InitEvpCtxError,
    InitDigestError,
    DigestUpdateError,
    DigestFinalError,
    HmacCtxNull,
    HmacInitError,
    HmacUpdateError,
    HmacFinalizeError,
    HasherNone,
    HmacHashError,
    UnsupportedHasher(String),
}

impl Display for HashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HashError::UnsupportedHasher(v) => write!(f, "unsupported hasher-{}", v),
            _ => write!(f, "{:?}", self)
        }
    }
}

impl Error for HashError {}