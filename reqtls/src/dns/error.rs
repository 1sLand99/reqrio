use std::error::Error;
use std::fmt::Display;
use std::str::Utf8Error;
use crate::BufferError;

#[derive(Debug)]
pub enum DNSError {
    NotFoundNameLen,
    InvalidName(Utf8Error),
    Buffer(BufferError),
}

impl Display for DNSError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for DNSError {}