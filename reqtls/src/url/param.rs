use std::borrow::Cow;
use super::error::UrlError;
use crate::coder;
use std::fmt::{Display, Formatter};
use crate::error::RlsResult;

#[derive(Debug, Clone)]
pub struct Param {
    name: String,
    equal_sign: bool,
    value: String,
}

impl Default for Param {
    fn default() -> Self {
        Param {
            name: "".to_string(),
            equal_sign: true,
            value: "".to_string(),
        }
    }
}

impl Param {
    pub fn new_param<'a>(name: impl ToString, value: impl Into<Cow<'a, str>>) -> Param {
        Param {
            name: name.to_string(),
            equal_sign: true,
            value: coder::url_encode(value).into_owned(),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn value_raw(&self) -> &str { &self.value }

    pub fn value(&self) -> RlsResult<Cow<'_, str>> {
        coder::url_decode(&self.value).or(Err(UrlError::InvalidParamEncoded.into()))
    }

    pub fn into_value(self) -> RlsResult<String> {
        let value = coder::url_decode(&self.value).or(Err(UrlError::InvalidParamEncoded))?;
        Ok(value.into_owned())
    }

    pub fn set_value<'a>(&mut self, value: impl Into<Cow<'a, str>>) {
        self.value = coder::url_encode(value).into_owned();
    }

    pub fn is_empty(&self) -> bool {
        self.name.is_empty() && self.value.is_empty()
    }

    pub fn len(&self) -> usize {
        self.name.len() + 1 + self.value.len()
    }

    pub fn with_equal(mut self, equal: bool) -> Self {
        self.equal_sign = equal;
        self
    }

    pub fn set_equal(&mut self, equal: bool) {
        self.equal_sign = equal;
    }

    pub fn equal_sign(&self) -> bool {
        self.equal_sign
    }
}

impl Display for Param {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.equal_sign {
            true => write!(f, "{}={}", &self.name, &self.value),
            false => write!(f, "{}{}", &self.name, &self.value)
        }
    }
}

impl TryFrom<&str> for Param {
    type Error = UrlError;
    fn try_from(raw: &str) -> Result<Self, Self::Error> {
        let mut items = raw.split("=");
        let name = items.next().ok_or(UrlError::MissingParamName)?.to_string();
        let value = items.collect::<Vec<_>>().join("=");
        Ok(Param {
            name,
            equal_sign: raw.contains("="),
            value,
        })
    }
}

impl TryFrom<String> for Param {
    type Error = UrlError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Param::try_from(value.as_str())
    }
}