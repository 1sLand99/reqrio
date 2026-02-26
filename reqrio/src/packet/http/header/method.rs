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

impl Display for Method {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Method::GET => f.write_str("GET"),
            Method::POST => f.write_str("POST"),
            Method::OPTIONS => f.write_str("OPTIONS"),
            Method::HEAD => f.write_str("HEAD"),
            Method::PUT => f.write_str("PUT"),
            Method::DELETE => f.write_str("DELETE"),
            Method::CONNECT => f.write_str("CONNECT"),
            Method::TRACE => f.write_str("TRACE"),
            Method::PATCH => f.write_str("PATCH"),
        }
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