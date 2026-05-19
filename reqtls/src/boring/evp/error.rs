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
}