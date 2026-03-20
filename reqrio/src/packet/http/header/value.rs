use std::fmt::Display;
use crate::cookie::CookieManager;
use crate::packet::http::content_type::ContentType;
use crate::packet::http::cookie::Cookie;

#[derive(Clone)]
pub enum HeaderValue {
    String(String),
    Bool(bool),
    Number(usize),
    ContextType(ContentType),
    Cookies(CookieManager),
}

impl HeaderValue {
    pub fn add_cookie(&mut self, cookie: Cookie) {
        if let HeaderValue::Cookies(cookies) = self {
            cookies.push(cookie);
        }
    }

    pub fn as_string(&self) -> Option<&str> {
        match self {
            HeaderValue::String(v) => Some(v),
            _ => None
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            HeaderValue::String(v) => v.is_empty(),
            HeaderValue::Bool(_) => false,
            HeaderValue::Number(v) => *v == 0,
            HeaderValue::ContextType(_) => false,
            HeaderValue::Cookies(v) => v.is_empty(),
        }
    }

    pub fn may_len(&self) -> usize {
        match self {
            HeaderValue::String(v) => v.len(),
            HeaderValue::Bool(_) => 1,
            HeaderValue::Number(_) => 10,
            HeaderValue::ContextType(_) => 64,
            HeaderValue::Cookies(cookies) => cookies.req_may_len()
        }
    }
}

impl Display for HeaderValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HeaderValue::String(v) => f.write_str(v),
            HeaderValue::Bool(v) => f.write_str(if *v { "1" } else { "0" }),
            HeaderValue::Number(v) => f.write_str(v.to_string().as_str()),
            HeaderValue::ContextType(v) => f.write_str(v.to_string().as_str()),
            HeaderValue::Cookies(v) => write!(f, "{}", v)
        }
    }
}