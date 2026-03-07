use std::error::Error;
use std::fmt::{Display, Formatter};
use super::super::huffman::HuffmanError;

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

impl From<HuffmanError> for HPackError {
    fn from(value: HuffmanError) -> Self {
        HPackError::Currently(value.to_string())
    }
}
impl Error for HPackError {}

