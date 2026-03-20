use super::param::Param;
use crate::error::RlsResult;
use crate::RlsError;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone)]
pub struct Uri {
    path: String,
    params: Vec<Param>,
    len: usize,
}

impl Default for Uri {
    fn default() -> Self {
        Uri {
            path: "".to_string(),
            params: vec![],
            len: 0,
        }
    }
}

impl Uri {
    pub fn path(&self) -> &str { &self.path }

    pub fn new_path(path: impl ToString) -> Uri {
        let path = path.to_string();
        Uri {
            len: path.len(),
            path: path.to_string(),
            params: vec![],
        }
    }

    pub fn set_path(&mut self, path: impl ToString) {
        self.path = path.to_string();
        self.len = path.to_string().len();
    }

    pub fn parse_param(&mut self, item: &str) -> RlsResult<()> {
        self.params.clear();
        for kv in item.split("&") {
            self.params.push(Param::try_from(kv)?);
        }
        self.len += item.len();
        Ok(())
    }

    pub fn insert_param(&mut self, name: impl ToString, value: impl ToString) {
        let name = name.to_string();
        let value = value.to_string();
        let param = self.params.iter_mut().find(|x| x.name() == name);
        match param {
            None => {
                self.len += name.len() + value.len() + 1;
                self.params.push(Param::new_param(name, value))
            }
            Some(param) => {
                self.len = self.len - param.value().len() + value.len();
                param.set_value(value)
            }
        }
    }

    pub fn remove_param(&mut self, name: impl ToString) -> Option<String> {
        let name = name.to_string();
        let pos = self.params.iter().position(|x| x.name() == name)?;
        self.len -= name.len() + self.params[pos].value().len() + 1;
        Some(self.params.remove(pos).take_value())
    }

    pub fn params(&self) -> &Vec<Param> { &self.params }

    pub fn params_mut(&mut self) -> &mut Vec<Param> { &mut self.params }

    pub fn len(&self) -> usize { self.len }

    pub fn clear_params(&mut self) {
        self.params.clear();
        self.len = self.path.len();
    }
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
        let mut res = Uri::new_path(items.next().unwrap_or(""));
        if let Some(param) = items.next() {
            res.parse_param(param)?;
        }
        Ok(res)
    }
}