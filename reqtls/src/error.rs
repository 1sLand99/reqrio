use std::array::TryFromSliceError;
use std::convert::Infallible;
use std::error::Error;
use std::ffi::NulError;
use std::fmt::{Display, Formatter};
use std::io;
use std::num::ParseIntError;
use std::string::FromUtf8Error;
use hex::FromHexError;

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
    HmacCtxNull,
    HmacInitError,
    HmacUpdateError,
    HmacFinalizeError,
    InitEvpCtxError,
    InitDigestError,
    DigestUpdateError,
    DigestFinalError,
    DigestSignError,
    DigestVerifyError,
    RsaNewError,
    BnNewError,
    BnSetWordError,
    RsaGenKeyError,
    PkeyNewError,
    PkeyAssignError,
    BioNewError,
    WritePriKeyError,
    WritePubKeyError,
    RsaSetPaddingError,
    PkeyEncryptError,
    InitEncryptError,
    InitDecryptError,
    PkeyDecryptError,
    OpenX509Error,
    SetRsaMgf1MdError,
    SetRsaPassSaltLenError,
    CertSniInvalid,
    GenEcPubKeyError,
    SkNewError,
    SkPushError,
    X509StoreNewError,
    X509StoreCtxNewError,
    X509StoreCtxInitError,
    X509StoreAddError,
    IssuerUnknown,
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
            RlsError::InvalidCipherSuite => f.write_str("Invalid suite suite"),
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
            RlsError::HmacCtxNull => f.write_str("Hmac ctx null"),
            RlsError::HmacInitError => f.write_str("Hmac init error"),
            RlsError::HmacUpdateError => f.write_str("Hmac update error"),
            RlsError::HmacFinalizeError => f.write_str("Hmac finalize error"),
            RlsError::InitEvpCtxError => f.write_str("Init Evp ctx error"),
            RlsError::InitDigestError => f.write_str("Init digest error"),
            RlsError::DigestUpdateError => f.write_str("Digest update error"),
            RlsError::DigestFinalError => f.write_str("Digest finalize error"),
            RlsError::DigestSignError => f.write_str("Digest sign error"),
            RlsError::DigestVerifyError => f.write_str("Digest verify error"),
            RlsError::RsaNewError => f.write_str("Rsa new error"),
            RlsError::BnNewError => f.write_str("Bn new error"),
            RlsError::BnSetWordError => f.write_str("Bn set word error"),
            RlsError::RsaGenKeyError => f.write_str("Rsa gen key error"),
            RlsError::PkeyNewError => f.write_str("Pkey new error"),
            RlsError::PkeyAssignError => f.write_str("Pkey assign error"),
            RlsError::BioNewError => f.write_str("Bio new error"),
            RlsError::WritePriKeyError => f.write_str("Write private key error"),
            RlsError::WritePubKeyError => f.write_str("Write public key error"),
            RlsError::RsaSetPaddingError => f.write_str("Rsa set padding error"),
            RlsError::PkeyEncryptError => f.write_str("Pkey encrypt error"),
            RlsError::InitDecryptError => f.write_str("Init decrypt error"),
            RlsError::PkeyDecryptError => f.write_str("Pkey decrypt error"),
            RlsError::InitEncryptError => f.write_str("Init encrypt error"),
            RlsError::OpenX509Error => f.write_str("Open X509 error"),
            RlsError::SetRsaMgf1MdError => f.write_str("Set Rsa Mgf1Md error"),
            RlsError::SetRsaPassSaltLenError => f.write_str("Set Rsa Pass Salt Len error"),
            RlsError::CertSniInvalid => f.write_str("cert sni error"),
            RlsError::GenEcPubKeyError => f.write_str("gen ec public key error"),
            RlsError::SkNewError => f.write_str("Sk new error"),
            RlsError::SkPushError => f.write_str("sk push error"),
            RlsError::X509StoreNewError=> f.write_str("X509 store new error"),
            RlsError::X509StoreCtxNewError=> f.write_str("X509 store ctx new error"),
            RlsError::X509StoreCtxInitError=> f.write_str("X509 store ctx init error"),
            RlsError::X509StoreAddError=> f.write_str("X509 store add error"),
            RlsError::IssuerUnknown=> f.write_str("Issuer unknown"),
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

impl From<NulError> for RlsError {
    fn from(value: NulError) -> Self {
        RlsError::StdError(Box::new(value))
    }
}

impl From<&[u8]> for RlsError {
    fn from(value: &[u8]) -> Self {
        match value {
            b"unable to get local issuer certificate"=>RlsError::IssuerUnknown,
            _ => RlsError::Currently(String::from_utf8_lossy(value).to_string()),
        }
    }
}

impl Error for RlsError {}

pub type RlsResult<T> = Result<T, RlsError>;