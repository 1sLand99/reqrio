mod sm2;

pub use sm2::{Sm2Key, Sm2Model};


#[derive(Debug)]
pub enum SmError {
    Sm2KeyNew,
    Sm2GenKeyFailed,
    Sm2VerifyFailed,
    Sm2SignError,
    Sm2EncryptError,
    Sm2DecryptFail,
    Sm2GetKeyFailed,
}