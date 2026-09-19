use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum ConnError {
    GenSecretKeyFailed,
    SecretPubKeyNull,
    DiffieHellmanFailed,
    MissingClientConfig,
    MissingServerConfig,
}

impl Error for ConnError {}

impl Display for ConnError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}


