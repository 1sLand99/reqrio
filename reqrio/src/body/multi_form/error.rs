use std::error::Error;
use std::fmt::Display;

#[derive(Debug)]
pub enum FormError {
    GetFilenameError,
}

impl Display for FormError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { FormError::GetFilenameError => write!(f, "get filename error"), }
    }
}

impl Error for FormError {}
