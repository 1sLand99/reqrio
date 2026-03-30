use std::fmt::{Debug, Display, Formatter};
use std::io;
use std::num::{ParseFloatError, ParseIntError};
use std::path::Path;
use std::pin::Pin;
use std::slice::{Iter, IterMut};
use std::string::FromUtf8Error;
use std::task::{Context, Poll};
use std::vec::IntoIter;
use serde::{Deserialize, Serialize};
use serde_json::{to_string_pretty, Error};
use object::Object;
use crate::number::Number;
use crate::object::{ObjectIntoIter, ObjectIter, ObjectIterMut};

mod object;
mod json_impl;
pub mod number;
pub mod ext;
pub use serde_json::Value;

pub struct JsonError {
    msg: String,
}

impl Debug for JsonError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.msg)
    }
}

impl Display for JsonError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.msg)
    }
}

unsafe impl Send for JsonError {}

impl Future for JsonError {
    type Output = String;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(self.msg.clone())
    }
}

impl From<&str> for JsonError {
    fn from(msg: &str) -> Self {
        JsonError { msg: msg.to_string() }
    }
}

impl From<ParseFloatError> for JsonError {
    fn from(err: ParseFloatError) -> Self {
        JsonError { msg: err.to_string() }
    }
}

impl From<io::Error> for JsonError {
    fn from(value: io::Error) -> Self {
        JsonError { msg: value.to_string() }
    }
}

impl From<FromUtf8Error> for JsonError {
    fn from(value: FromUtf8Error) -> Self {
        JsonError { msg: value.to_string() }
    }
}

impl From<ParseIntError> for JsonError {
    fn from(value: ParseIntError) -> Self {
        JsonError { msg: value.to_string() }
    }
}

impl From<Error> for JsonError {
    fn from(value: Error) -> Self {
        JsonError { msg: value.to_string() }
    }
}

impl std::error::Error for JsonError {}


type JsonResult<T> = Result<T, JsonError>;

static NULL: JsonValue = JsonValue::Null;

pub fn parse(source: impl AsRef<str>) -> JsonResult<JsonValue> {
    Ok(serde_json::from_str(source.as_ref())?)
}

pub fn from_file(fp: impl AsRef<Path>) -> JsonResult<JsonValue> {
    let b = std::fs::read(fp.as_ref())?;
    let s = String::from_utf8(b)?;
    parse(s.as_str())
}

pub fn from_bytes(context: impl AsRef<[u8]>) -> JsonResult<JsonValue> {
    let s = String::from_utf8(context.as_ref().to_vec())?;
    parse(s.as_str())
}

pub fn to_string<T: Serialize>(t: &T) -> JsonResult<String> {
    Ok(serde_json::to_string(t)?)
}

pub fn to_struct<T: for<'de> serde::Deserialize<'de>>(value:Value)->serde_json::Result<T>{
    serde_json::from_value(value)
}

pub fn from_struct<T: Serialize>(t: &T) -> JsonResult<JsonValue> {
    let s = to_string(t)?;
    parse(s.as_str())
}


#[derive(Clone)]
pub enum JsonValue {
    Null,
    String(String),
    Number(Number),
    Boolean(bool),
    Object(Object),
    Array(Vec<JsonValue>),
}

impl Display for JsonValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if f.alternate() {
            f.write_str(&self.pretty())
        } else {
            f.write_str(self.dump().as_str())
        }
    }
}

impl JsonValue {
    pub fn new_object() -> JsonValue {
        JsonValue::Object(Object::new())
    }

    pub fn new_array() -> JsonValue {
        JsonValue::Array(vec![])
    }

    pub fn push<T>(&mut self, value: T)
    where
        T: Into<JsonValue>,
    {
        if let JsonValue::Array(vec) = self { vec.push(value.into()) }
    }

    pub fn len(&self) -> usize {
        match *self {
            JsonValue::Array(ref vec) => vec.len(),
            JsonValue::Object(ref object) => object.len(),
            _ => 0
        }
    }

    pub fn keys(&self) -> JsonResult<Vec<&str>> {
        match self {
            JsonValue::Object(obj) => Ok(obj.nodes().iter().map(|x| x.key()).collect()),
            _ => Err("not json object".into())
        }
    }

    pub fn insert<T>(&mut self, key: &str, value: T) -> JsonResult<()>
    where
        T: Into<JsonValue>,
    {
        match self {
            JsonValue::Object(o) => Ok(o.insert(key, value.into())),
            _ => Err("Wrong Type Object!".into())
        }
    }

    pub fn pretty(&self) -> String {
        match self {
            JsonValue::Null => "null".to_string(),
            JsonValue::String(v) => v.clone(),
            _ => to_string_pretty(self).unwrap()
        }
    }

    pub fn dump(&self) -> String {
        match self {
            JsonValue::Null => "null".to_string(),
            JsonValue::String(v) => v.clone(),
            _ => to_string(self).unwrap()
        }
    }

    pub fn has_key(&self, key: &str) -> bool {
        match *self {
            JsonValue::Object(ref object) => !object.get(key).is_null(),
            _ => false
        }
    }

    pub fn members(&self) -> Iter<'_, JsonValue> {
        match self {
            JsonValue::Array(vec) => vec.iter(),
            _ => [].iter()
        }
    }

    pub fn members_mut(&mut self) -> IterMut<'_, JsonValue> {
        match self {
            JsonValue::Array(vec) => vec.iter_mut(),
            _ => [].iter_mut()
        }
    }

    pub fn into_members(self) -> IntoIter<JsonValue> {
        match self {
            JsonValue::Array(vec) => vec.into_iter(),
            _ => vec![].into_iter()
        }
    }

    pub fn entries(&self) -> ObjectIter<'_> {
        match self {
            JsonValue::Object(object) => object.iter(),
            _ => ObjectIter::empty()
        }
    }

    pub fn entries_mut(&mut self) -> ObjectIterMut<'_> {
        match self {
            JsonValue::Object(object) => object.iter_mut(),
            _ => ObjectIterMut::empty()
        }
    }

    pub fn into_entries(self) -> ObjectIntoIter {
        match self {
            JsonValue::Object(object) => object.into_iter(),
            _ => ObjectIntoIter::empty()
        }
    }

    pub fn clear(&mut self) {
        match self {
            JsonValue::String(string) => string.clear(),
            JsonValue::Object(object) => object.clear(),
            JsonValue::Array(vec) => vec.clear(),
            _ => *self = JsonValue::Null,
        }
    }

    pub fn remove(&mut self, key: &str) -> JsonValue {
        match self {
            JsonValue::Object(object) => object.remove(key),
            _ => JsonValue::Null,
        }
    }

    pub fn array_remove(&mut self, index: usize) -> JsonValue {
        match self {
            JsonValue::Array(array) => { array.remove(index) }
            _ => JsonValue::Null
        }
    }

    /// must update_first
    pub fn as_struct<T: for<'a> Deserialize<'a>>(&self) -> JsonResult<T> {
        let s = self.dump();
        Ok(serde_json::from_str(s.as_str())?)
    }

    pub fn write_file(&self, fp: impl AsRef<Path>) -> JsonResult<()> {
        std::fs::write(fp.as_ref(), self.pretty())?;
        Ok(())
    }

    fn update_object(json1: &mut JsonValue, json2: JsonValue) -> JsonResult<()> {
        for (k, v) in json2.into_entries() {
            if v.is_object() && json1[k.as_str()].is_object() {
                Self::update_object(&mut json1[k], v)?;
                continue;
            } else if v.is_array() && json1[k.as_str()].is_array() {
                Self::update_array(&mut json1[k], v)?;
                continue;
            }
            json1.insert(&k, v)?;
        }
        Ok(())
    }

    fn update_array(json1: &mut JsonValue, json2: JsonValue) -> JsonResult<()> {
        for (i, v) in json2.into_members().enumerate() {
            if v.is_object() && json1[i].is_object() {
                Self::update_object(&mut json1[i], v)?;
                continue;
            } else if v.is_array() && json1[i].is_array() {
                Self::update_array(&mut json1[i], v)?;
                continue;
            }
            json1[i] = v;
        }
        Ok(())
    }

    pub fn update_by(&mut self, other: JsonValue) -> JsonResult<()> {
        if other.is_object() && self.is_object() {
            Self::update_object(self, other)
        } else if other.is_array() && self.is_array() {
            Self::update_array(self, other)
        } else {
            *self = other;
            Ok(())
        }
    }

    fn set_by_xpath(&mut self, xp: &[String], value: JsonValue) -> JsonResult<()> {
        if !xp.is_empty() {
            if xp[0].starts_with("[") && xp[0].ends_with("]") {
                if !self.is_array() { return Err("xpath error-current is not array".into()); }
                let index = xp[0].replace("[", "").replace("]", "").parse::<usize>()?;
                self[index].set_by_xpath(&xp[1..], value)?;
            } else {
                if !self.is_object() { return Err("xpath error-current is not object".into()); }
                self[xp[0].as_str()].set_by_xpath(&xp[1..], value)?;
            };
        } else {
            *self = value;
        }
        Ok(())
    }

    pub fn set_value_by_xpath<T: Into<JsonValue>>(&mut self, xpath: &str, other: T) -> JsonResult<()> {
        let paths = xpath.split('.').collect::<Vec<_>>();
        let xpaths = paths.iter().filter_map(|x| if x != &"" { Some(x.to_string()) } else { None }).collect::<Vec<_>>();
        self.set_by_xpath(xpaths.as_slice(), other.into())?;
        Ok(())
    }

    fn get_by_xpath(&self, xp: &[String]) -> JsonResult<&JsonValue> {
        if !xp.is_empty() {
            if xp[0].starts_with("[") && xp[0].ends_with("]") {
                if !self.is_array() { return Err("xpath error-current is not array".into()); }
                let index = xp[0].replace("[", "").replace("]", "").parse::<usize>()?;
                self[index].get_by_xpath(&xp[1..])
            } else {
                if !self.is_object() { return Err("xpath error-current is not object".into()); }
                self[xp[0].as_str()].get_by_xpath(&xp[1..])
            }
        } else {
            Ok(self)
        }
    }

    pub fn xpath(&self, xpath: &str) -> JsonResult<&JsonValue> {
        let paths = xpath.split('.').collect::<Vec<_>>();
        let xpaths = paths.iter().filter_map(|x| if x != &"" { Some(x.to_string()) } else { None }).collect::<Vec<_>>();
        self.get_by_xpath(xpaths.as_slice())
    }

    fn remove_by_xpath(&mut self, xp: &[String]) -> JsonResult<JsonValue> {
        if xp.len() == 1 {
            if xp[0].starts_with("[") && xp[0].ends_with("]") {
                if !self.is_array() { return Err("xpath error-current is not array".into()); }
                let index = xp[0].replace("[", "").replace("]", "").parse::<usize>()?;
                Ok(self.array_remove(index))
            } else {
                if !self.is_object() { return Err("xpath error-current is not object".into()); }
                Ok(self.remove(xp[0].as_str()))
            }
        } else if xp[0].starts_with("[") && xp[0].ends_with("]") {
            if !self.is_array() { return Err("xpath error-current is not array".into()); }
            let index = xp[0].replace("[", "").replace("]", "").parse::<usize>()?;
            self[index].remove_by_xpath(&xp[1..])
        } else {
            if !self.is_object() { return Err("xpath error-current is not object".into()); }
            self[xp[0].as_str()].remove_by_xpath(&xp[1..])
        }
    }

    pub fn remove_value_by_xpath(&mut self, xpath: &str) -> JsonResult<JsonValue> {
        let paths = xpath.split('.').collect::<Vec<_>>();
        let xpaths = paths.iter().filter_map(|x| if x != &"" { Some(x.to_string()) } else { None }).collect::<Vec<_>>();
        if xpaths.is_empty() { return Err("xpath error".into()); }
        self.remove_by_xpath(xpaths.as_slice())
    }

    pub fn into_key(mut self, key: impl AsRef<str>) -> JsonValue {
        self.remove(key.as_ref())
    }

    pub fn into_index(mut self, index: usize) -> JsonValue {
        self.array_remove(index)
    }
}

impl Debug for JsonValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.dump().as_str())
    }
}

unsafe impl Send for JsonValue {}


/// ```
/// # use reqrio_json as json;
/// # fn main() {
/// let data = json::array!["foo", 42, false];
/// # }
/// ```
#[macro_export]
macro_rules! array {
    [] => ($crate::JsonValue::new_array());

    // Handles for token tree items
    [@ITEM($( $i:expr, )*) $item:tt, $( $cont:tt )+] => {
        $crate::array!(
            @ITEM($( $i, )* $crate::value!($item), )
            $( $cont )*
        )
    };
    (@ITEM($( $i:expr, )*) $item:tt,) => ({
        $crate::array!(@END $( $i, )* $crate::value!($item), )
    });
    (@ITEM($( $i:expr, )*) $item:tt) => ({
        $crate::array!(@END $( $i, )* $crate::value!($item), )
    });

    // Handles for expression items
    [@ITEM($( $i:expr, )*) $item:expr, $( $cont:tt )+] => {
        $crate::array!(
            @ITEM($( $i, )* $crate::value!($item), )
            $( $cont )*
        )
    };
    (@ITEM($( $i:expr, )*) $item:expr,) => ({
        $crate::array!(@END $( $i, )* $crate::value!($item), )
    });
    (@ITEM($( $i:expr, )*) $item:expr) => ({
        $crate::array!(@END $( $i, )* $crate::value!($item), )
    });

    // Construct the actual array
    (@END $( $i:expr, )*) => ({
        let size = 0 $( + {let _ = &$i; 1} )*;
        let mut array = Vec::with_capacity(size);

        $(
            array.push($i.into());
        )*

        $crate::JsonValue::Array(array)
    });

    // Entry point to the macro
    ($( $cont:tt )+) => {
        $crate::array!(@ITEM() $($cont)*)
    };
}

#[macro_export]
/// Helper crate for converting types into `JsonValue`. It's used
/// internally by the `object!` and `array!` macros.
macro_rules! value {
    ( null ) => { $crate::JsonValue::Null };
    ( [$( $token:tt )*] ) => {
        // 10
        $crate::array![ $( $token )* ]
    };
    ( {$( $token:tt )*} ) => {
        $crate::object!{ $( $token )* }
    };
    { $value:expr } => { $value };
}

/// Helper macro for creating instances of `JsonValue::Object`.
///
/// ```
/// # use reqrio_json as json;
/// # fn main() {
/// let data = json::object!{
///     foo: 42,
///     bar: false,
/// };
/// # }
/// ```
#[macro_export]
macro_rules! object {
    // Empty object.
    {} => ($crate::JsonValue::new_object());

    // Handles for different types of keys
    (@ENTRY($( $k:expr => $v:expr, )*) $key:ident: $( $cont:tt )*) => {
        $crate::object!(@ENTRY($( $k => $v, )*) stringify!($key) => $($cont)*)
    };
    (@ENTRY($( $k:expr => $v:expr, )*) $key:literal: $( $cont:tt )*) => {
        $crate::object!(@ENTRY($( $k => $v, )*) $key => $($cont)*)
    };
    (@ENTRY($( $k:expr => $v:expr, )*) [$key:expr]: $( $cont:tt )*) => {
        $crate::object!(@ENTRY($( $k => $v, )*) $key => $($cont)*)
    };

    // Handles for token tree values
    (@ENTRY($( $k:expr => $v:expr, )*) $key:expr => $value:tt, $( $cont:tt )+) => {
        $crate::object!(
            @ENTRY($( $k => $v, )* $key => $crate::value!($value), )
            $( $cont )*
        )
    };
    (@ENTRY($( $k:expr => $v:expr, )*) $key:expr => $value:tt,) => ({
        $crate::object!(@END $( $k => $v, )* $key => $crate::value!($value), )
    });
    (@ENTRY($( $k:expr => $v:expr, )*) $key:expr => $value:tt) => ({
        $crate::object!(@END $( $k => $v, )* $key => $crate::value!($value), )
    });

    // Handles for expression values
    (@ENTRY($( $k:expr => $v:expr, )*) $key:expr => $value:expr, $( $cont:tt )+) => {
        $crate::object!(
            @ENTRY($( $k => $v, )* $key => $crate::value!($value), )
            $( $cont )*
        )
    };
    (@ENTRY($( $k:expr => $v:expr, )*) $key:expr => $value:expr,) => ({
        $crate::object!(@END $( $k => $v, )* $key => $crate::value!($value), )
    });

    (@ENTRY($( $k:expr => $v:expr, )*) $key:expr => $value:expr) => ({
        $crate::object!(@END $( $k => $v, )* $key => $crate::value!($value), )
    });

    // Construct the actual object
    (@END $( $k:expr => $v:expr, )*) => ({
        // let size = 0 $( + {let _ = &$k; 1} )*;
        let mut object = $crate::JsonValue::new_object();


        $(
            let s=$crate::JsonValue::from($v);
            object.insert($k, s).unwrap();
        )*
        object
        //$crat// e::JsonValue::Object(object)
    });

    // Entry point to the macro
    ($key:tt: $( $cont:tt )+) => {
        $crate::object!(@ENTRY() $key: $($cont)*)
    };

    // Legacy macro
    ($( $k:expr => $v:expr, )*) => {
        $crate::object!(@END $( $k => $crate::value!($v), )*)
    };
    ($( $k:expr => $v:expr ),*) => {
        $crate::object!(@END $( $k => $crate::value!($v), )*)
    };
}





