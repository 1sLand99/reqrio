use super::pkey_ctx::PKeyError;

#[derive(Debug)]
pub enum EvpError {
    InitEvpPKeyCtx,
    InitKeygen,
    KeyGen,
    GetPubKey,
    InitDerive,
    SetPeerDerive,
    NewPublicKey,
    Derive,
    PKey(PKeyError),
}

impl From<PKeyError> for EvpError {
    fn from(err: PKeyError) -> Self {
        EvpError::PKey(err)
    }
}