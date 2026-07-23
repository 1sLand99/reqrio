use std::array::TryFromSliceError;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::ops::Range;

#[derive(Debug)]
pub enum BufferError {
    ///内容长度过小
    Insufficient,
    InvalidQUICVariant,
    CapacityTooSmall { needed: usize, current: usize },
    Overflow { capacity: usize, len: usize, need: usize },
    IndexOutBound { size: usize, index: usize },
    RangeEdgeError(Range<usize>),
    Nullptr,
    ResizeFail { current: usize, new: usize },
    SliceConvertError(TryFromSliceError),
}

impl Display for BufferError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            BufferError::Insufficient => write!(f, "Insufficient decoding data"),
            BufferError::CapacityTooSmall { needed, current } => write!(f, "The required capacity is {}, but the actual capacity is {}.", needed, current),
            BufferError::Overflow { capacity, len, need } => write!(f, "The buffer capacity is {}, but write {} out of it.", capacity, len + need),
            BufferError::IndexOutBound { size, index } => write!(f, "The index {} out of bounds {} ", index, size),
            BufferError::RangeEdgeError(range) => write!(f, "The range is {:?} of Buffer is fail", range),
            BufferError::Nullptr => write!(f, "Nullptr"),
            BufferError::ResizeFail { current, new } => write!(f, "resize to {} fail from {}", new, current),
            BufferError::InvalidQUICVariant => write!(f, "Invalid variant"),
            BufferError::SliceConvertError(er)=> write!(f, "SliceConvertError({})", er),
        }
    }
}

impl Error for BufferError {}

impl From<TryFromSliceError> for BufferError {
    fn from(value: TryFromSliceError) -> Self {
        BufferError::SliceConvertError(value)
    }
}