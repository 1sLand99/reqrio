use std::fmt::{Debug, Display, Formatter};

#[derive(Clone)]
pub struct HPackItem {
    name: String,
    value: String,
}


impl Display for HPackItem {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(format!("HPack(\"{}\",\"{}\")", self.name, self.value).as_str())
    }
}

impl Debug for HPackItem {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.to_string().as_str())
    }
}

impl HPackItem {
    pub fn new(name: impl ToString, value: impl ToString) -> HPackItem {
        HPackItem {
            name: name.to_string(),
            value: value.to_string(),
        }
    }

    pub fn new_table_size(size: usize) -> HPackItem {
        HPackItem {
            name: "update-table-size".to_string(),
            value: size.to_string(),
        }
    }

    pub fn name_value(&self) -> String {
        format!("{}: {}", self.name, self.value)
    }
    pub fn with_value(mut self, value: impl ToString) -> HPackItem {
        self.value = value.to_string();
        self
    }
    pub fn set_name(&mut self, name: impl ToString) {
        self.name = name.to_string();
    }
    pub fn set_value(&mut self, value: impl ToString) {
        self.value = value.to_string();
    }
    pub fn name(&self) -> &str { &self.name }
    pub fn value(&self) -> &str { &self.value }

    /// 条目大小=len(name)+len(value)+32
    ///
    /// 文档rfc7541-4.1
    pub fn item_size(&self) -> usize {
        self.name.len() + self.value.len() + 32
    }
}