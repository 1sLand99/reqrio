use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum HPackError {
    InvalidIndex,
    InvalidPrefix,
    IntegerOverflow,
    Currently(String),
}

impl Display for HPackError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            HPackError::InvalidIndex => write!(f, "invalid index"),
            HPackError::InvalidPrefix => write!(f, "invalid prefix"),
            HPackError::IntegerOverflow => write!(f, "integer overflow"),
            HPackError::Currently(e) => write!(f, "{}", e),
        }
    }
}

impl Error for HPackError {}

