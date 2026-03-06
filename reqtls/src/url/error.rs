use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum UrlError {
    ParseUrlError,
    ParseUriError,
    MissingParamName,
    MissingScheme,
    MissingDomain,
    MissingUsername,
    MissingPassword,
    AuthInfoError,
    InvalidParamEncoded,
    InvalidScheme(String),
    InvalidPort,
}

impl Display for UrlError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            UrlError::ParseUrlError => write!(f, "parse url error"),
            UrlError::ParseUriError => write!(f, "parse uri error"),
            UrlError::MissingParamName => write!(f, "missing param name"),
            UrlError::MissingScheme => write!(f, "missing scheme"),
            UrlError::MissingDomain => write!(f, "missing domain"),
            UrlError::MissingUsername => write!(f, "missing username"),
            UrlError::MissingPassword => write!(f, "missing password"),
            UrlError::AuthInfoError => write!(f, "auth info error"),
            UrlError::InvalidParamEncoded => write!(f, "invalid param encoding"),
            UrlError::InvalidScheme(v) => write!(f, "invalid scheme-({})", v),
            UrlError::InvalidPort => write!(f, "invalid port"),
        }
    }
}

impl Error for UrlError {}