use std::collections::HashMap;
use std::error::Error;
use std::ops::{Index, IndexMut};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use crate::{JsonResult, JsonValue, NULL};
use crate::number::Number;
use crate::parser::JsonParser;

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

impl Serialize for JsonValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let ser_str = match self {
            JsonValue::String(s) => format!("\"{s}\""),
            _ => { self.dump() }
        };
        let json_value: Value = serde_json::from_str(&ser_str).unwrap();
        serializer.serialize_some(&json_value)
    }
}

impl<'de> Deserialize<'de> for JsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let json_value: Value = Deserialize::deserialize(deserializer)?;
        let json_str = serde_json::to_string(&json_value).unwrap();
        Ok(JsonParser::new().parse_json(mh_json::parse(json_str.as_str()).unwrap()).unwrap())
    }
}

impl JsonValue {

    pub fn is_string(&self) -> bool {
        match *self {
            JsonValue::String(_) => true,
            _ => false,
        }
    }

    pub fn is_number(&self) -> bool {
        match *self {
            JsonValue::Number(_) => true,
            _ => false,
        }
    }

    pub fn is_boolean(&self) -> bool {
        match *self {
            JsonValue::Boolean(_) => true,
            _ => false
        }
    }

    pub fn is_null(&self) -> bool {
        match *self {
            JsonValue::Null => true,
            _ => false,
        }
    }

    pub fn is_object(&self) -> bool {
        match *self {
            JsonValue::Object(_) => true,
            _ => false,
        }
    }

    pub fn is_array(&self) -> bool {
        match *self {
            JsonValue::Array(_) => true,
            _ => false,
        }
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
        match *self {
            JsonValue::Boolean(ref value) => Ok(value.clone()),
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


impl Into<mh_json::JsonValue> for JsonValue {
    fn into(self) -> mh_json::JsonValue {
        match self {
            JsonValue::Null => mh_json::Null,
            JsonValue::String(s) => mh_json::JsonValue::String(s),
            JsonValue::Number(n) => {
                match n {
                    Number::U8(v) => mh_json::JsonValue::Number(mh_json::number::Number::from(v)),
                    Number::U16(v) => mh_json::JsonValue::Number(mh_json::number::Number::from(v)),
                    Number::U32(v) => mh_json::JsonValue::Number(mh_json::number::Number::from(v)),
                    Number::U64(v) => mh_json::JsonValue::Number(mh_json::number::Number::from(v)),
                    Number::U128(v) => mh_json::JsonValue::Number(mh_json::number::Number::from(v as u64)),
                    Number::Usize(v) => mh_json::JsonValue::Number(mh_json::number::Number::from(v)),
                    Number::I8(v) => mh_json::JsonValue::Number(mh_json::number::Number::from(v)),
                    Number::I16(v) => mh_json::JsonValue::Number(mh_json::number::Number::from(v)),
                    Number::I32(v) => mh_json::JsonValue::Number(mh_json::number::Number::from(v)),
                    Number::I64(v) => mh_json::JsonValue::Number(mh_json::number::Number::from(v)),
                    Number::I128(v) => mh_json::JsonValue::Number(mh_json::number::Number::from(v as i64)),
                    Number::Isize(v) => mh_json::JsonValue::Number(mh_json::number::Number::from(v)),
                    Number::F32(v) => mh_json::JsonValue::Number(mh_json::number::Number::from(v)),
                    Number::F64(v) => mh_json::JsonValue::Number(mh_json::number::Number::from(v))
                }
            }
            JsonValue::Boolean(b) => mh_json::JsonValue::Boolean(b),
            JsonValue::Object(o) => o.into(),
            JsonValue::Array(a) => a.into()
        }
    }
}