use crate::json::JsonError;
use httlib_hpack::DecoderError;
use crate::hpack::HPackError;
use reqtls::{hex, Alert, RlsError, ALPN};
use std::array::TryFromSliceError;
use std::convert::Infallible;
use std::error::Error;
use std::ffi::NulError;
use std::fmt::{Display, Formatter};
use std::io;
use std::net::AddrParseError;
use std::num::ParseIntError;
use std::str::Utf8Error;
use std::string::FromUtf8Error;
use std::sync::PoisonError;
#[cfg(feature = "aync")]
use tokio::time::error::Elapsed;

#[derive(Debug)]
pub enum HlsError {
    NullPointer,
    InvalidHeadSize,
    PeerClosedConnection,
    PayloadNone,
    DecrypterNone,
    EncrypterNone,
    WsFrameTypeNone,
    DataTooShort,
    Currently(String),
}

impl From<&str> for HlsError {
    fn from(s: &str) -> Self {
        HlsError::Currently(s.to_string())
    }
}

impl From<String> for HlsError {
    fn from(s: String) -> Self {
        HlsError::Currently(s)
    }
}

impl From<FromUtf8Error> for HlsError {
    fn from(e: FromUtf8Error) -> Self {
        HlsError::Currently(e.to_string())
    }
}

impl From<ParseIntError> for HlsError {
    fn from(e: ParseIntError) -> Self {
        HlsError::Currently(e.to_string())
    }
}

impl Display for HlsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            HlsError::Currently(e) => f.write_str(e),
            HlsError::InvalidHeadSize => f.write_str("InvalidHeadSize"),
            HlsError::PeerClosedConnection => f.write_str("PeerClosedConnection"),
            HlsError::PayloadNone => f.write_str("PayloadNone"),
            HlsError::DecrypterNone => f.write_str("DecrypterNone"),
            HlsError::NullPointer => f.write_str("NonePointer"),
            HlsError::EncrypterNone => f.write_str("EncrypterNone"),
            HlsError::WsFrameTypeNone => f.write_str("WsFrameTypeNone"),
            HlsError::DataTooShort => f.write_str("DataTooShort"),
        }
    }
}

impl From<TryFromSliceError> for HlsError {
    fn from(value: TryFromSliceError) -> Self {
        HlsError::Currently(value.to_string())
    }
}

impl From<io::Error> for HlsError {
    fn from(value: io::Error) -> Self {
        HlsError::Currently(value.to_string())
    }
}

impl From<Infallible> for HlsError {
    fn from(value: Infallible) -> Self {
        HlsError::Currently(value.to_string())
    }
}

impl From<HPackError> for HlsError {
    fn from(value: HPackError) -> Self {
        HlsError::Currently(value.to_string())
    }
}

impl From<DecoderError> for HlsError {
    fn from(value: DecoderError) -> Self {
        HlsError::Currently(value.to_string())
    }
}

impl From<JsonError> for HlsError {
    fn from(value: JsonError) -> Self {
        HlsError::Currently(value.to_string())
    }
}

impl<T: 'static> From<PoisonError<T>> for HlsError {
    fn from(value: PoisonError<T>) -> Self {
        HlsError::Currently(value.to_string())
    }
}

impl From<Utf8Error> for HlsError {
    fn from(value: Utf8Error) -> Self {
        HlsError::Currently(value.to_string())
    }
}

impl From<RlsError> for HlsError {
    fn from(value: RlsError) -> Self {
        HlsError::Currently(value.to_string())
    }
}

#[cfg(feature = "aync")]
impl From<Elapsed> for HlsError {
    fn from(value: Elapsed) -> Self {
        HlsError::Currently(value.to_string())
    }
}

impl From<HlsError> for io::Error {
    fn from(err: HlsError) -> io::Error {
        io::Error::other(err.to_string())
    }
}

impl From<AddrParseError> for HlsError {
    fn from(value: AddrParseError) -> Self {
        HlsError::Currently(value.to_string())
    }
}

impl From<hex::FromHexError> for HlsError {
    fn from(value: hex::FromHexError) -> Self {
        HlsError::Currently(value.to_string())
    }
}

impl From<NulError> for HlsError {
    fn from(value: NulError) -> Self {
        HlsError::Currently(value.to_string())
    }
}

impl From<Alert> for HlsError {
    fn from(value: Alert) -> Self {
        HlsError::Currently(value.to_string())
    }
}

impl From<BufferError> for HlsError {
    fn from(value: BufferError) -> Self {
        HlsError::Currently(value.to_string())
    }
}

impl Error for HlsError {}

unsafe impl Send for HlsError {}

#[derive(Debug)]
pub enum BufferError {
    UnsupportedALPN(ALPN),
    BufferTooSmall(usize),
}

impl Display for BufferError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            BufferError::UnsupportedALPN(alpn) => write!(f, "UnsupportedALPN: {}", alpn),
            BufferError::BufferTooSmall(size) => write!(f, "BufferTooSmall: {}", size),
        }
    }
}

impl Error for BufferError {}


pub type HlsResult<T> = Result<T, HlsError>;
