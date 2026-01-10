use std::collections::HashMap;
use std::error::Error;
use std::ops::{Index, IndexMut};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use crate::number::Number;
use crate::object::Object;
use crate::{JsonResult, JsonValue, NULL};

impl Index<usize> for JsonValue {
    type Output = JsonValue;

    fn index(&self, index: usize) -> &Self::Output {
        match self {
            JsonValue::Array(vec) => vec.get(index).unwrap_or(&NULL),
            _ => &NULL
        }
    }
}

impl IndexMut<usize> for JsonValue {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        match self {
            JsonValue::Array(vec) => {
                let in_bounds = index < vec.len();
                if in_bounds {
                    &mut vec[index]
                } else {
                    vec.push(JsonValue::Null);
                    vec.last_mut().unwrap()
                }
            }
            _ => {
                *self = JsonValue::Array(vec![]);
                self.push(JsonValue::Null);
                self.index_mut(index)
            }
        }
    }
}

impl<'a> Index<&'a str> for JsonValue {
    type Output = JsonValue;

    fn index(&self, index: &str) -> &JsonValue {
        match *self {
            JsonValue::Object(ref object) => &object[index],
            _ => &NULL
        }
    }
}

impl Index<String> for JsonValue {
    type Output = JsonValue;

    fn index(&self, index: String) -> &JsonValue {
        self.index(index.as_str())
    }
}

impl<'a> Index<&'a String> for JsonValue {
    type Output = JsonValue;

    fn index(&self, index: &String) -> &JsonValue {
        self.index(index.as_str())
    }
}

impl<'a> IndexMut<&'a str> for JsonValue {
    fn index_mut(&mut self, index: &str) -> &mut JsonValue {
        match *self {
            JsonValue::Object(ref mut object) => {
                &mut object[index]
            }
            _ => {
                *self = JsonValue::new_object();
                self.index_mut(index)
            }
        }
    }
}

impl IndexMut<String> for JsonValue {
    fn index_mut(&mut self, index: String) -> &mut JsonValue {
        self.index_mut(index.as_str())
    }
}

impl<'a> IndexMut<&'a String> for JsonValue {
    fn index_mut(&mut self, index: &String) -> &mut JsonValue {
        self.index_mut(index.as_str())
    }
}

impl JsonValue {
    pub fn is_string(&self) -> bool {
        matches!(self, JsonValue::String(_))
    }

    pub fn is_number(&self) -> bool {
        matches!(self, JsonValue::Number(_))
    }

    pub fn is_boolean(&self) -> bool {
        matches!(self, JsonValue::Boolean(_))
    }

    pub fn is_null(&self) -> bool {
        matches!(self, JsonValue::Null)
    }

    pub fn is_object(&self) -> bool {
        matches!(self, JsonValue::Object(_))
    }

    pub fn is_array(&self) -> bool {
        matches!(self, JsonValue::Array(_))
    }

    pub fn as_str(&self) -> JsonResult<&str> {
        match *self {
            JsonValue::String(ref value) => Ok(value),
            _ => Err("parse str error!".into())
        }
    }

    pub fn as_number(&self) -> JsonResult<Number> {
        match self {
            JsonValue::Number(value) => Ok(value.clone()),
            JsonValue::String(s) => Ok(Number::F64(s.parse::<f64>().or(Err("str to number error!"))?)),
            _ => Err("not number json value!".into())
        }
    }

    pub fn as_f64(&self) -> JsonResult<f64> {
        Ok(self.as_number()?.as_f64())
    }

    pub fn as_f32(&self) -> JsonResult<f32> {
        Ok(self.as_number()?.as_f32())
    }

    pub fn as_u64(&self) -> JsonResult<u64> {
        Ok(self.as_number()?.as_u64())
    }

    pub fn as_u32(&self) -> JsonResult<u32> {
        Ok(self.as_number()?.as_u32())
    }

    pub fn as_u16(&self) -> JsonResult<u16> {
        Ok(self.as_number()?.as_u16())
    }

    pub fn as_u8(&self) -> JsonResult<u8> {
        Ok(self.as_number()?.as_u8())
    }

    pub fn as_usize(&self) -> JsonResult<usize> {
        Ok(self.as_number()?.as_usize())
    }

    pub fn as_i64(&self) -> JsonResult<i64> {
        Ok(self.as_number()?.as_i64())
    }

    pub fn as_i32(&self) -> JsonResult<i32> {
        Ok(self.as_number()?.as_i32())
    }

    pub fn as_i16(&self) -> JsonResult<i16> {
        Ok(self.as_number()?.as_i16())
    }

    pub fn as_i8(&self) -> JsonResult<i8> {
        Ok(self.as_number()?.as_i8())
    }

    pub fn as_isize(&self) -> JsonResult<isize> {
        Ok(self.as_number()?.as_isize())
    }

    pub fn as_bool(&self) -> JsonResult<bool> {
        match self {
            JsonValue::Boolean(value) => Ok(*value),
            _ => Err("parse bool error!".into())
        }
    }
}

impl From<String> for JsonValue {
    fn from(value: String) -> Self {
        JsonValue::String(value)
    }
}

impl<'a> From<&'a str> for JsonValue {
    fn from(value: &'a str) -> Self {
        JsonValue::String(value.to_string())
    }
}

impl<'a> From<&'a String> for JsonValue {
    fn from(value: &'a String) -> Self {
        JsonValue::String(value.to_string())
    }
}

impl From<i8> for JsonValue {
    fn from(value: i8) -> Self {
        JsonValue::Number(Number::I8(value))
    }
}

impl From<&i8> for JsonValue {
    fn from(value: &i8) -> Self {
        JsonValue::Number(Number::I8(*value))
    }
}

impl From<i16> for JsonValue {
    fn from(value: i16) -> Self {
        JsonValue::Number(Number::I16(value))
    }
}

impl From<&i16> for JsonValue {
    fn from(value: &i16) -> Self {
        JsonValue::Number(Number::I16(*value))
    }
}

impl From<i32> for JsonValue {
    fn from(value: i32) -> Self {
        JsonValue::Number(Number::I32(value))
    }
}

impl From<&i32> for JsonValue {
    fn from(value: &i32) -> Self {
        JsonValue::Number(Number::I32(*value))
    }
}

impl From<i64> for JsonValue {
    fn from(value: i64) -> Self {
        JsonValue::Number(Number::I64(value))
    }
}

impl From<&i64> for JsonValue {
    fn from(value: &i64) -> Self {
        JsonValue::Number(Number::I64(*value))
    }
}

impl From<i128> for JsonValue {
    fn from(value: i128) -> Self {
        JsonValue::Number(Number::I128(value))
    }
}

impl From<&i128> for JsonValue {
    fn from(value: &i128) -> Self {
        JsonValue::Number(Number::I128(*value))
    }
}

impl From<isize> for JsonValue {
    fn from(value: isize) -> Self {
        JsonValue::Number(Number::Isize(value))
    }
}

impl From<u8> for JsonValue {
    fn from(value: u8) -> Self {
        JsonValue::Number(Number::U8(value))
    }
}

impl From<&u8> for JsonValue {
    fn from(value: &u8) -> Self {
        JsonValue::Number(Number::U8(*value))
    }
}

impl From<u16> for JsonValue {
    fn from(value: u16) -> Self {
        JsonValue::Number(Number::U16(value))
    }
}

impl From<&u16> for JsonValue {
    fn from(value: &u16) -> Self {
        JsonValue::Number(Number::U16(*value))
    }
}

impl From<u32> for JsonValue {
    fn from(value: u32) -> Self {
        JsonValue::Number(Number::U32(value))
    }
}

impl From<&u32> for JsonValue {
    fn from(value: &u32) -> Self {
        JsonValue::Number(Number::U32(*value))
    }
}

impl From<u64> for JsonValue {
    fn from(value: u64) -> Self {
        JsonValue::Number(Number::U64(value))
    }
}

impl From<&u64> for JsonValue {
    fn from(value: &u64) -> Self {
        JsonValue::Number(Number::U64(*value))
    }
}

impl From<u128> for JsonValue {
    fn from(value: u128) -> Self {
        JsonValue::Number(Number::U128(value))
    }
}

impl From<&u128> for JsonValue {
    fn from(value: &u128) -> Self {
        JsonValue::Number(Number::U128(*value))
    }
}

impl From<usize> for JsonValue {
    fn from(value: usize) -> Self {
        JsonValue::Number(Number::I64(value as i64))
    }
}

impl From<f32> for JsonValue {
    fn from(value: f32) -> Self {
        JsonValue::Number(Number::F32(value))
    }
}

impl From<&f32> for JsonValue {
    fn from(value: &f32) -> Self {
        JsonValue::Number(Number::F32(*value))
    }
}

impl From<f64> for JsonValue {
    fn from(value: f64) -> Self {
        JsonValue::Number(Number::F64(value))
    }
}

impl From<&f64> for JsonValue {
    fn from(value: &f64) -> Self {
        JsonValue::Number(Number::F64(*value))
    }
}


impl From<bool> for JsonValue {
    fn from(value: bool) -> Self {
        JsonValue::Boolean(value)
    }
}

impl From<&bool> for JsonValue {
    fn from(value: &bool) -> Self {
        JsonValue::Boolean(*value)
    }
}

impl<T> From<Vec<T>> for JsonValue
where
    T: Into<JsonValue>,
{
    fn from(value: Vec<T>) -> Self {
        let mut array = JsonValue::new_array();
        for v in value {
            array.push(v.into());
        }
        array
    }
}


impl<'a, T> From<HashMap<&'a str, T>> for JsonValue
where
    T: Into<JsonValue>,
{
    fn from(value: HashMap<&'a str, T>) -> Self {
        let mut object = JsonValue::new_object();
        for (k, v) in value {
            object.insert(k, v.into()).unwrap();
        }
        object
    }
}

impl<T> From<HashMap<String, T>> for JsonValue
where
    T: Into<JsonValue>,
{
    fn from(value: HashMap<String, T>) -> Self {
        let mut object = JsonValue::new_object();
        for (k, v) in value {
            object.insert(k.as_str(), v.into()).unwrap();
        }
        object
    }
}

impl<'a, T: Clone> From<&'a [T]> for JsonValue
where
    T: Into<JsonValue>,
{
    fn from(value: &'a [T]) -> Self {
        let mut array = JsonValue::new_array();
        for v in value {
            array.push(v.clone().into())
        };
        array
    }
}

impl<T> From<Option<T>> for JsonValue
where
    T: Into<JsonValue>,
{
    fn from(value: Option<T>) -> Self {
        match value {
            None => { JsonValue::Null }
            Some(v) => { v.into() }
        }
    }
}

impl Into<Box<dyn Error>> for JsonValue {
    fn into(self) -> Box<dyn Error> {
        Box::from(self.to_string())
    }
}

impl Serialize for JsonValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            JsonValue::Null => Value::Null.serialize(serializer),
            JsonValue::String(v) => v.serialize(serializer),
            JsonValue::Number(v) => v.serialize(serializer),
            JsonValue::Boolean(v) => v.serialize(serializer),
            JsonValue::Object(v) => v.serialize(serializer),
            JsonValue::Array(v) => v.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for JsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        Ok(JsonValue::try_from(value).or(Err(serde::de::Error::custom("to json value error")))?)
    }
}

impl TryFrom<Value> for JsonValue {
    type Error = serde::de::value::Error;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        match value {
            Value::Null => Ok(JsonValue::Null),
            Value::Bool(v) => Ok(JsonValue::Boolean(v)),
            Value::Number(v) => Ok(JsonValue::Number(Number::try_from(v).or(Err(serde::de::Error::custom("to number error")))?)),
            Value::String(v) => Ok(JsonValue::String(v)),
            Value::Array(v) => {
                let mut array = JsonValue::new_array();
                for value in v {
                    array.push(JsonValue::try_from(value)?);
                }
                Ok(array)
            }
            Value::Object(v) => Ok(JsonValue::Object(Object::try_from(v)?))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::JsonValue;

    #[test]
    fn test_object() {
        let jd = crate::object! {
            "sdsd":"dffdf",
            "dfdf":[1,2,3,4],
            "dfdg":null,
            "tf":1,
            "fs":false,
            "sf":1.23234,
            "dffdfdf":{
                "1":1,
                "2":2,
                "3":3,
            }
        };
        let strs = serde_json::to_string_pretty(&jd).unwrap();
        println!("{}", strs);
        let v: JsonValue = serde_json::from_str(&strs).unwrap();
        println!("{}", v.pretty());
        println!("{} {}", v["sdsd"].to_string(), v["tf"].pretty())
    }
}