use super::pkey_ctx::PKeyError;

#[derive(Debug)]
pub enum EvpError {
    InitEvpPKeyCtxError,
    InitKeygenError,
    KeyGenError,
    GetPubKeyError,
    InitDeriveError,
    SetPeerDeriveError,
    NewPublicKeyError,
    DeriveError,
    PKeyError(PKeyError),
}

impl From<PKeyError> for EvpError {
    fn from(err: PKeyError) -> Self {
        EvpError::PKeyError(err)
    }
}