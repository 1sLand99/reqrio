use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum HPackError {
    BufferTooSmall,
    InvalidIndexType(u8),
    InvalidLenIndex,
    IndexedItemNone,
    NameIndexedItemNone,

    InvalidPrefix,
    IntegerOverflow,
    Currently(String),
}

impl Display for HPackError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            HPackError::BufferTooSmall => write!(f, "buffer too small"),
            HPackError::InvalidIndexType(v) => write!(f, "invalid index type: {:0b}", v),
            HPackError::InvalidLenIndex => write!(f, "invalid length index"),
            HPackError::IndexedItemNone => write!(f, "index item none"),
            HPackError::NameIndexedItemNone => write!(f, "name index item none"),
            HPackError::InvalidPrefix => write!(f, "invalid prefix"),
            HPackError::IntegerOverflow => write!(f, "integer overflow"),
            HPackError::Currently(e) => write!(f, "{}", e),
        }
    }
}

impl Error for HPackError {}

