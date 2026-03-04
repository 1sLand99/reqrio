use super::param::Param;
use crate::error::RlsResult;
use crate::RlsError;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone)]
pub struct Uri {
    path: String,
    params: Vec<Param>,
}

impl Default for Uri {
    fn default() -> Self {
        Uri {
            path: "".to_string(),
            params: vec![],
        }
    }
}

impl Uri {
    pub fn value(&self) -> &str { &self.path }

    pub fn set_uri(&mut self, uri: impl ToString) {
        self.path = uri.to_string();
    }

    pub fn parse_param(&mut self, item: &str) -> RlsResult<()> {
        self.params.clear();
        for kv in item.split("&") {
            self.params.push(Param::try_from(kv)?);
        }
        Ok(())
    }

    pub fn insert_param(&mut self, name: impl ToString, value: impl ToString) {
        let name = name.to_string();
        let param = self.params.iter_mut().find(|x| x.name() == &name);
        match param {
            None => self.params.push(Param::new_param(name, value)),
            Some(param) => param.set_value(value),
        }
    }

    pub fn remove_param(&mut self, name: impl ToString) -> Option<String> {
        let name = name.to_string();
        let pos = self.params.iter().position(|x| x.name() == &name)?;
        Some(self.params.remove(pos).take_value())
    }

    pub fn params(&self) -> &Vec<Param> { &self.params }

    pub fn params_mut(&mut self) -> &mut Vec<Param> {
        &mut self.params
    }

    pub fn clear_params(&mut self) {
        self.params.clear();
    }

    pub fn without_param(&self) -> &str { &self.path }
}

impl Display for Uri {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let param = self.params.iter().map(|p| p.to_string()).collect::<Vec<_>>().join("&");
        if param.is_empty() {
            f.write_str(&self.path)
        } else {
            f.write_str(&format!("{}?{}", self.path, param))
        }
    }
}

impl TryFrom<&str> for Uri {
    type Error = RlsError;
    fn try_from(value: &str) -> RlsResult<Uri> {
        let mut items = value.split("?");
        let mut res = Uri::default();
        res.path = items.next().unwrap_or("").to_string();
        if let Some(param) = items.next() {
            res.parse_param(param)?;
        }
        Ok(res)
    }
}