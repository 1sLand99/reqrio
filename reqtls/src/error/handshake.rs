use std::fmt::{Display, Formatter};
use crate::Version;

#[derive(Debug)]
pub enum HandShakeError {
    UnsupportedVersion(Version),
    VerifyFinishedFail,
    PollWhileFinish,

}

impl Display for HandShakeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}