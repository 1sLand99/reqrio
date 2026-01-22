use std::array::TryFromSliceError;
use std::convert::Infallible;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::io;
use std::num::ParseIntError;
use std::string::FromUtf8Error;
// use aws_lc_rs::error::Unspecified;
use hex::FromHexError;
use hmac::digest::InvalidLength;

#[derive(Debug)]
pub enum RlsError {
    ClientHelloNone,
    EncrypterNone,
    DecrypterNone,
    PayloadNone,
    GenKeyFromAeadNone,
    HasherNone,
    AeadNone,
    InvalidCipherSuite,
    MessageTooShort,
    AeadCryptError,
    AeadEncryptError,
    AeadDecryptError,
    CipherCryptError,
    CipherEncryptError,
    CipherDecryptError,
    CipherMacError,
    InitEcKeyError,
    GenEcKeyError,
    InitEcPointError,
    OCT2PointError,
    ComputeKeyError,
    InitEvpPKeyCtxError,
    InitKeygenError,
    KeyGenError,
    GetPubKeyError,
    NewPublicKeyError,
    InitDeriveError,
    SetPeerDeriveError,
    DeriveError,
    StdError(Box<dyn Error>),
    Currently(String),
}

impl Display for RlsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            RlsError::ClientHelloNone => f.write_str("Client hello none"),
            RlsError::EncrypterNone => f.write_str("Encrypter none"),
            RlsError::DecrypterNone => f.write_str("Decrypter none"),
            RlsError::PayloadNone => f.write_str("Payload none"),
            RlsError::GenKeyFromAeadNone => f.write_str("get key from aead none"),
            RlsError::AeadNone => f.write_str("Aead none"),
            RlsError::HasherNone => f.write_str("Hasher none"),
            RlsError::InvalidCipherSuite => f.write_str("Invalid cipher suite"),
            RlsError::MessageTooShort => f.write_str("Message too short"),
            RlsError::AeadCryptError => f.write_str("Init aead crypto error"),
            RlsError::AeadEncryptError => f.write_str("Aead encrypt error"),
            RlsError::AeadDecryptError => f.write_str("Aead decrypt error"),
            RlsError::CipherCryptError => f.write_str("Cipher crypto error"),
            RlsError::CipherEncryptError => f.write_str("Cipher encrypt error"),
            RlsError::CipherDecryptError => f.write_str("Cipher decrypt error"),
            RlsError::CipherMacError => f.write_str("Cipher mac error"),
            RlsError::InitEcKeyError => f.write_str("Init EC key error"),
            RlsError::GenEcKeyError => f.write_str("Gen EC key error"),
            RlsError::InitEcPointError => f.write_str("Init EC point error"),
            RlsError::OCT2PointError => f.write_str("OCT2 EC point error"),
            RlsError::ComputeKeyError => f.write_str("Compute key error"),
            RlsError::InitEvpPKeyCtxError => f.write_str("Init Evp P key ctx error"),
            RlsError::InitKeygenError => f.write_str("Init keygen error"),
            RlsError::KeyGenError => f.write_str("Key gen error"),
            RlsError::GetPubKeyError => f.write_str("Get public key error"),
            RlsError::NewPublicKeyError => f.write_str("New public key error"),
            RlsError::InitDeriveError => f.write_str("Init derive error"),
            RlsError::SetPeerDeriveError => f.write_str("Set peer derive error"),
            RlsError::DeriveError => f.write_str("Derive error"),
            RlsError::StdError(e) => f.write_fmt(format_args!("{:?}", e)),
            RlsError::Currently(e) => f.write_str(e),
        }
    }
}

impl From<String> for RlsError {
    fn from(e: String) -> Self {
        RlsError::Currently(e)
    }
}

impl From<&str> for RlsError {
    fn from(e: &str) -> Self {
        RlsError::Currently(e.to_string())
    }
}

impl From<Infallible> for RlsError {
    fn from(e: Infallible) -> Self {
        RlsError::StdError(Box::new(e))
    }
}

impl From<FromUtf8Error> for RlsError {
    fn from(value: FromUtf8Error) -> Self {
        RlsError::StdError(Box::new(value))
    }
}

impl From<TryFromSliceError> for RlsError {
    fn from(value: TryFromSliceError) -> Self {
        RlsError::StdError(Box::new(value))
    }
}

impl From<InvalidLength> for RlsError {
    fn from(value: InvalidLength) -> Self {
        RlsError::StdError(Box::new(value))
    }
}

impl From<io::Error> for RlsError {
    fn from(value: io::Error) -> Self {
        RlsError::StdError(Box::new(value))
    }
}

impl From<FromHexError> for RlsError {
    fn from(value: FromHexError) -> Self {
        RlsError::StdError(Box::new(value))
    }
}

impl From<ParseIntError> for RlsError {
    fn from(value: ParseIntError) -> Self {
        RlsError::StdError(Box::new(value))
    }
}

impl From<RlsError> for io::Error {
    fn from(error: RlsError) -> Self {
        io::Error::new(io::ErrorKind::Other, error.to_string())
    }
}

impl Error for RlsError {}

pub type RlsResult<T> = Result<T, RlsError>;