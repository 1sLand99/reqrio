use std::borrow::Cow;
use super::value::HeaderValue;
use crate::packet::http::cookie::Cookie;

#[derive(Clone)]
pub struct HeaderKey {
    name: Cow<'static, str>,
    value: HeaderValue,
    reserved: bool,
}

impl HeaderKey {
    pub fn none() -> HeaderKey {
        HeaderKey {
            name: Cow::Borrowed(""),
            value: HeaderValue::String("".to_string()),
            reserved: false,
        }
    }

    pub fn new(name: impl ToString, value: impl Into<HeaderValue>) -> HeaderKey {
        HeaderKey {
            name: Cow::Owned(name.to_string()),
            value: value.into(),
            reserved: false,
        }
    }

    #[cfg(feature = "export")]
    pub(crate) fn with_reserved(mut self, reserved: bool) -> HeaderKey {
        self.reserved = reserved;
        self
    }

    ///保留的key，当key的值为空时，该值不会被发送; 若要发送请使用new
    pub fn new_reserved(name: &'static str, value: impl Into<HeaderValue>) -> HeaderKey {
        HeaderKey {
            name: Cow::Borrowed(name),
            value: value.into(),
            reserved: true,
        }
    }

    pub fn cookies(&self) -> Option<&[Cookie]> {
        match self.value {
            HeaderValue::Cookies(ref cookies) => Some(cookies.inner()),
            _ => None,
        }
    }

    pub fn name(&self) -> &str { &self.name }

    pub fn name_lower(&self) -> String { self.name.to_lowercase() }

    pub fn value(&self) -> &HeaderValue { &self.value }

    pub fn value_mut(&mut self) -> &mut HeaderValue { &mut self.value }

    pub fn set_value(&mut self, value: HeaderValue) {
        self.value = value;
    }

    pub fn into_value(self) -> HeaderValue { self.value }

    pub(crate) fn is_reserved(&self) -> bool { self.reserved }
}