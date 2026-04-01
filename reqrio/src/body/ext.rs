use std::borrow::Cow;
use super::{Body, BodyKind};
use crate::ContentType;
use reqrio_json::JsonValue;

pub trait BodyExt {
    fn ty(&self, ct: ContentType) -> Body<'_>;
}

pub trait BodyData {
    fn form(&self) -> Body<'_>;
}

impl BodyExt for JsonValue {
    fn ty(&self, ct: ContentType) -> Body<'_> {
        Body {
            kind: BodyKind::Data(Cow::Borrowed(self)),
            ct,
        }
    }
}

impl BodyData for JsonValue {
    fn form(&self) -> Body<'_> {
        Body {
            kind: BodyKind::Data(Cow::Borrowed(self)),
            ct: ContentType::form(),
        }
    }
}


impl BodyExt for String {
    fn ty(&self, ct: ContentType) -> Body<'_> {
        Body {
            kind: BodyKind::Bytes(Cow::Borrowed(self.as_bytes())),
            ct,
        }
    }
}

impl BodyExt for &str {
    fn ty(&self, ct: ContentType) -> Body<'_> {
        Body {
            kind: BodyKind::Bytes(Cow::Borrowed(self.as_bytes())),
            ct,
        }
    }
}

impl BodyExt for &[u8] {
    fn ty(&self, ct: ContentType) -> Body<'_> {
        Body {
            kind: BodyKind::Bytes(Cow::Borrowed(self)),
            ct,
        }
    }
}

impl BodyExt for Vec<u8> {
    fn ty(&self, ct: ContentType) -> Body<'_> {
        Body {
            kind: BodyKind::Bytes(Cow::Borrowed(self)),
            ct,
        }
    }
}

impl<const N: usize> BodyExt for [u8; N] {
    fn ty(&self, ct: ContentType) -> Body<'_> {
        Body {
            kind: BodyKind::Bytes(Cow::Borrowed(self)),
            ct,
        }
    }
}