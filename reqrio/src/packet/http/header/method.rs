use std::fmt::{Display, Formatter};
use crate::error::HlsError;

#[derive(Clone, Copy)]
#[cfg_attr(feature = "export", repr(C))]
pub enum Method {
    GET = 0,
    POST = 1,
    PUT = 2,
    HEAD = 3,
    DELETE = 4,
    OPTIONS = 5,
    TRACE = 6,
    CONNECT = 7,
    PATCH = 8,
}

impl Method {
    pub fn spec(&self) -> &str {
        match self {
            Method::GET => "GET",
            Method::POST => "POST",
            Method::PUT => "PUT",
            Method::HEAD => "HEAD",
            Method::DELETE => "DELETE",
            Method::OPTIONS => "OPTIONS",
            Method::TRACE => "TRACE",
            Method::CONNECT => "CONNECT",
            Method::PATCH => "PATCH",
        }
    }
}

impl Display for Method {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.spec())
    }
}

impl TryFrom<&str> for Method {
    type Error = HlsError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Method::try_from(value.as_bytes())
    }
}

impl TryFrom<String> for Method {
    type Error = HlsError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Method::try_from(value.as_bytes())
    }
}

impl TryFrom<&[u8]> for Method {
    type Error = HlsError;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        match value {
            b"GET" => Ok(Method::GET),
            b"POST" => Ok(Method::POST),
            b"OPTIONS" => Ok(Method::OPTIONS),
            b"HEAD" => Ok(Method::HEAD),
            b"PUT" => Ok(Method::PUT),
            b"DELETE" => Ok(Method::DELETE),
            b"CONNECT" => Ok(Method::CONNECT),
            b"TRACE" => Ok(Method::TRACE),
            b"PATCH" => Ok(Method::PATCH),
            _ => Err("Invalid HTTP method".into())
        }
    }
}