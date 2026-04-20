use std::error::Error;
use std::fmt::{Display, Formatter};
use std::io;
use crate::message::HandshakeType;
use crate::Version;

#[derive(Debug)]
pub enum HandShakeError {
    UnsupportedVersion(Version),
    VerifyFinishedFail,
    PollWhileFinish,
    RetryNoKeyShare,
    UnknownRecord(u8),
    UnsupportedMessage(HandshakeType),
}

impl Display for HandShakeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for HandShakeError {}

impl From<HandShakeError> for io::Error {
    fn from(e: HandShakeError) -> Self {
        io::Error::other(e)
    }
}