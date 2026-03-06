use std::fmt::Display;
use crate::packet::http::content_type::ContentType;
use crate::packet::http::cookie::Cookie;

#[derive(Clone)]
pub enum HeaderValue {
    String(String),
    Bool(bool),
    Number(usize),
    ContextType(ContentType),
    Cookies(Vec<Cookie>),
}

impl HeaderValue {
    pub fn add_cookie(&mut self, cookie: Cookie) {
        if let HeaderValue::Cookies(cookies) = self {
            let exits = cookies.iter_mut().find(|x| x.name() == cookie.name());
            if let Some(exits) = exits {
                *exits = cookie;
            } else {
                cookies.push(cookie)
            }
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
}

impl Display for HeaderValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HeaderValue::String(v) => f.write_str(v),
            HeaderValue::Bool(v) => f.write_str(if *v { "1" } else { "0" }),
            HeaderValue::Number(v) => f.write_str(v.to_string().as_str()),
            HeaderValue::ContextType(v) => f.write_str(v.to_string().as_str()),
            HeaderValue::Cookies(v) => {
                let v = v.iter().map(|x| x.as_req()).collect::<Vec<_>>();
                f.write_str(v.join("; ").as_str())
            }
        }
    }
}