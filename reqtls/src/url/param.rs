use std::borrow::Cow;
use super::error::UrlError;
use crate::coder;
use std::fmt::{Display, Formatter};
use crate::error::RlsResult;

#[derive(Debug, Clone)]
pub struct Param {
    name: String,
    ///编码后的值
    value: String,
}

impl Default for Param {
    fn default() -> Self {
        Param {
            name: "".to_string(),
            value: "".to_string(),
        }
    }
}

impl Param {
    pub fn new_param<'a>(name: impl ToString, value: impl Into<Cow<'a, str>>) -> Param {
        Param {
            name: name.to_string(),
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
}

impl Display for Param {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}={}", &self.name, &self.value)
    }
}

impl TryFrom<&str> for Param {
    type Error = UrlError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut items = value.split("=");
        let name = items.next().ok_or(UrlError::MissingParamName)?.to_string();
        let value = items.collect::<Vec<_>>().join("=");
        Ok(Param {
            name,
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