use super::{Body, BodyKind};
use crate::reader::HCow;
use crate::ContentType;
use reqrio_json::JsonValue;
use std::borrow::Cow;

pub trait BodyExt {
    fn ty(&self, ct: impl Into<ContentType>) -> Body<'_>;
}

pub trait BodyData {
    fn form(&self) -> Body<'_>;
}

impl BodyExt for JsonValue {
    fn ty(&self, ct: impl Into<ContentType>) -> Body<'_> {
        Body {
            kind: BodyKind::Data(HCow::Borrowed(self)),
            ct: ct.into(),
        }
    }
}

impl BodyData for JsonValue {
    fn form(&self) -> Body<'_> {
        Body {
            kind: BodyKind::Data(HCow::Borrowed(self)),
            ct: ContentType::form(),
        }
    }
}


impl BodyExt for String {
    fn ty(&self, ct: impl Into<ContentType>) -> Body<'_> {
        Body {
            kind: BodyKind::Bytes(Cow::Borrowed(self.as_bytes())),
            ct: ct.into(),
        }
    }
}

impl BodyExt for &str {
    fn ty(&self, ct: impl Into<ContentType>) -> Body<'_> {
        Body {
            kind: BodyKind::Bytes(Cow::Borrowed(self.as_bytes())),
            ct: ct.into(),
        }
    }
}

impl BodyExt for &[u8] {
    fn ty(&self, ct: impl Into<ContentType>) -> Body<'_> {
        Body {
            kind: BodyKind::Bytes(Cow::Borrowed(self)),
            ct: ct.into(),
        }
    }
}

impl BodyExt for Vec<u8> {
    fn ty(&self, ct: impl Into<ContentType>) -> Body<'_> {
        Body {
            kind: BodyKind::Bytes(Cow::Borrowed(self)),
            ct: ct.into(),
        }
    }
}

impl<const N: usize> BodyExt for [u8; N] {
    fn ty(&self, ct: impl Into<ContentType>) -> Body<'_> {
        Body {
            kind: BodyKind::Bytes(Cow::Borrowed(self)),
            ct: ct.into(),
        }
    }
}