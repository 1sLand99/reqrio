use serde::{Deserialize, Serialize};
use crate::{JsonResult, JsonValue};

pub trait JsonExt
where
    Self: Serialize + for<'a> Deserialize<'a>,
{
    fn new() -> Self;
}

impl JsonValue {
    pub fn to_struct<T: JsonExt>(self) -> JsonResult<T> {
        let mut self_struct = crate::from_struct(&T::new())?;
        self_struct.update_by(self)?;
        self_struct.as_struct()
    }
}