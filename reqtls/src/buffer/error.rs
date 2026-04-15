use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum BufferError {
    ///内容长度过小
    Insufficient,
    CapacityTooSmall { needed: usize, current: usize },
    Overflow { capacity: usize, len: usize, need: usize },
    IndexOutBound { size: usize, index: usize },
    Nullptr,
}

impl Display for BufferError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            BufferError::Insufficient => write!(f, "Insufficient decoding data"),
            BufferError::CapacityTooSmall { needed, current } => write!(f, "The required capacity is {}, but the actual capacity is {}.", needed, current),
            BufferError::Overflow { capacity, len, need } => write!(f, "The buffer capacity is {}, but write {} out of it.", capacity, len + need),
            BufferError::IndexOutBound { size, index } => write!(f, "The index {} out of bounds {} ", index, size),
            BufferError::Nullptr => write!(f, "Nullptr"),
        }
    }
}

impl Error for BufferError {}