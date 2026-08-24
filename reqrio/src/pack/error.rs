use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum PackError {
    BufferTooSmall,
    InvalidIndexType(u8),
    InvalidLenIndex,
    IndexedItemNone,
    NameIndexedItemNone,
    InvalidPrefix,
    IntegerOverflow,
    BlockedStream(usize),
    Currently(String),
}

impl Display for PackError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for PackError {}

