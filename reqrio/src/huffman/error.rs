use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum HuffmanError {
    ByteEncodeInvalid
}

impl Display for HuffmanError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self { HuffmanError::ByteEncodeInvalid => write!(f, "byte encode invalid"), }
    }
}

impl Error for HuffmanError {}

