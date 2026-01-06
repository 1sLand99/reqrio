use crate::{JsonResult, JsonValue};
use crate::number::Number;

pub struct JsonParser {}

impl JsonParser {
    pub fn new() -> Self {
        JsonParser {}
    }

    fn parse_array(&self, array: Vec<mh_json::JsonValue>) -> JsonResult<JsonValue> {
        let mut array_json = JsonValue::new_array();
        for a in array {
            let item_json = self.parse_json(a)?;
            array_json.push(item_json);
        }
        Ok(array_json)
    }

    fn parse_number(&self, value: &mh_json::JsonValue) -> JsonResult<JsonValue> {
        if let Some(i) = value.as_i64() {
            Ok(JsonValue::Number(Number::I64(i)))
        } else if let Some(f) = value.as_f64() {
            Ok(JsonValue::Number(Number::F64(f)))
        } else if let Some(u) = value.as_u64() {
            Ok(JsonValue::Number(Number::U64(u)))
        } else {
            Err("parse number error!".into())
        }
    }

    fn parse_object(&self, value: mh_json::object::Object) -> JsonResult<JsonValue> {
        let mut res = JsonValue::new_object();
        for (k, v) in value.iter(){
            res.insert(k, self.parse_json(v.clone())?)?;
        }
        Ok(res)
    }

    pub fn parse_json(&self, value: mh_json::JsonValue) -> JsonResult<JsonValue> {
        match value {
            mh_json::JsonValue::Null => { Ok(JsonValue::Null) }
            mh_json::JsonValue::Short(s) => { Ok(JsonValue::String(s.to_string())) }
            mh_json::JsonValue::String(s) => { Ok(JsonValue::String(s)) }
            mh_json::JsonValue::Number(_) => { self.parse_number(&value) }
            mh_json::JsonValue::Boolean(b) => { Ok(JsonValue::Boolean(b)) }
            mh_json::JsonValue::Object(o) => { self.parse_object(o) }
            mh_json::JsonValue::Array(a) => { self.parse_array(a) }
        }
    }
}