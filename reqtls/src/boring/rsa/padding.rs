use crate::boring::bindings::*;

pub enum RsaPadding {
    NoPadding,
    Pkcs1,
    Pkcs1Oaep,
    Pkcs1Pss,
}

impl RsaPadding {
    pub(crate) fn as_i32(&self) -> i32 {
        match self {
            RsaPadding::NoPadding => RSA_NO_PADDING,
            RsaPadding::Pkcs1 => RSA_PKCS1_PADDING,
            RsaPadding::Pkcs1Oaep => RSA_PKCS1_OAEP_PADDING,
            RsaPadding::Pkcs1Pss => RSA_PKCS1_PSS_PADDING,
        }
    }
}