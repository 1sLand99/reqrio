use super::value::HeaderValue;
use crate::packet::http::cookie::Cookie;

#[derive(Clone)]
pub struct HeaderKey {
    name: String,
    value: HeaderValue,
    reserved: bool,
}

impl HeaderKey {
    pub fn none() -> HeaderKey {
        HeaderKey {
            name: "".to_string(),
            value: HeaderValue::String("".to_string()),
            reserved: false,
        }
    }

    pub fn new(name: impl ToString, value: HeaderValue) -> HeaderKey {
        HeaderKey {
            name: name.to_string(),
            value,
            reserved: false,
        }
    }

    pub(crate) fn new_reserved(name: impl ToString, value: HeaderValue) -> HeaderKey {
        HeaderKey{
            name:name.to_string(),
            value,
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

    pub fn take_value(self) -> HeaderValue { self.value }

    pub fn value_mut(&mut self) -> &mut HeaderValue { &mut self.value }

    pub fn set_value(&mut self, value: HeaderValue) {
        self.value = value;
    }

    pub fn into_value(self) -> HeaderValue { self.value }
    
    pub fn is_reserved(&self) -> bool { self.reserved }
}