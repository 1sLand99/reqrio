use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

#[derive(Clone)]
pub enum Number {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
    Usize(usize),
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    I128(i128),
    Isize(isize),
    F32(f32),
    F64(f64),
}

impl Number {
    pub fn as_u8(&self) -> u8 {
        match self {
            Number::U8(v) => *v,
            Number::U16(v) => *v as u8,
            Number::U32(v) => *v as u8,
            Number::U64(v) => *v as u8,
            Number::U128(v) => *v as u8,
            Number::Usize(v) => *v as u8,
            Number::I8(v) => *v as u8,
            Number::I16(v) => *v as u8,
            Number::I32(v) => *v as u8,
            Number::I64(v) => *v as u8,
            Number::I128(v) => *v as u8,
            Number::Isize(v) => *v as u8,
            Number::F32(v) => *v as u8,
            Number::F64(v) => *v as u8,
        }
    }

    pub fn as_u16(&self) -> u16 {
        match self {
            Number::U8(v) => *v as u16,
            Number::U16(v) => *v,
            Number::U32(v) => *v as u16,
            Number::U64(v) => *v as u16,
            Number::U128(v) => *v as u16,
            Number::Usize(v) => *v as u16,
            Number::I8(v) => *v as u16,
            Number::I16(v) => *v as u16,
            Number::I32(v) => *v as u16,
            Number::I64(v) => *v as u16,
            Number::I128(v) => *v as u16,
            Number::Isize(v) => *v as u16,
            Number::F32(v) => *v as u16,
            Number::F64(v) => *v as u16,
        }
    }

    pub fn as_u32(&self) -> u32 {
        match self {
            Number::U8(v) => *v as u32,
            Number::U16(v) => *v as u32,
            Number::U32(v) => *v,
            Number::U64(v) => *v as u32,
            Number::U128(v) => *v as u32,
            Number::Usize(v) => *v as u32,
            Number::I8(v) => *v as u32,
            Number::I16(v) => *v as u32,
            Number::I32(v) => *v as u32,
            Number::I64(v) => *v as u32,
            Number::I128(v) => *v as u32,
            Number::Isize(v) => *v as u32,
            Number::F32(v) => *v as u32,
            Number::F64(v) => *v as u32,
        }
    }

    pub fn as_u64(&self) -> u64 {
        match self {
            Number::U8(v) => *v as u64,
            Number::U16(v) => *v as u64,
            Number::U32(v) => *v as u64,
            Number::U64(v) => *v,
            Number::U128(v) => *v as u64,
            Number::Usize(v) => *v as u64,
            Number::I8(v) => *v as u64,
            Number::I16(v) => *v as u64,
            Number::I32(v) => *v as u64,
            Number::I64(v) => *v as u64,
            Number::I128(v) => *v as u64,
            Number::Isize(v) => *v as u64,
            Number::F32(v) => *v as u64,
            Number::F64(v) => *v as u64,
        }
    }

    pub fn as_u128(&self) -> u128 {
        match self {
            Number::U8(v) => *v as u128,
            Number::U16(v) => *v as u128,
            Number::U32(v) => *v as u128,
            Number::U64(v) => *v as u128,
            Number::U128(v) => *v,
            Number::Usize(v) => *v as u128,
            Number::I8(v) => *v as u128,
            Number::I16(v) => *v as u128,
            Number::I32(v) => *v as u128,
            Number::I64(v) => *v as u128,
            Number::I128(v) => *v as u128,
            Number::Isize(v) => *v as u128,
            Number::F32(v) => *v as u128,
            Number::F64(v) => *v as u128,
        }
    }

    pub fn as_usize(&self) -> usize {
        match self {
            Number::U8(v) => *v as usize,
            Number::U16(v) => *v as usize,
            Number::U32(v) => *v as usize,
            Number::U64(v) => *v as usize,
            Number::U128(v) => *v as usize,
            Number::Usize(v) => *v,
            Number::I8(v) => *v as usize,
            Number::I16(v) => *v as usize,
            Number::I32(v) => *v as usize,
            Number::I64(v) => *v as usize,
            Number::I128(v) => *v as usize,
            Number::Isize(v) => *v as usize,
            Number::F32(v) => *v as usize,
            Number::F64(v) => *v as usize,
        }
    }

    pub fn as_i8(&self) -> i8 {
        match self {
            Number::U8(v) => *v as i8,
            Number::U16(v) => *v as i8,
            Number::U32(v) => *v as i8,
            Number::U64(v) => *v as i8,
            Number::U128(v) => *v as i8,
            Number::Usize(v) => *v as i8,
            Number::I8(v) => *v,
            Number::I16(v) => *v as i8,
            Number::I32(v) => *v as i8,
            Number::I64(v) => *v as i8,
            Number::I128(v) => *v as i8,
            Number::Isize(v) => *v as i8,
            Number::F32(v) => *v as i8,
            Number::F64(v) => *v as i8,
        }
    }

    pub fn as_i16(&self) -> i16 {
        match self {
            Number::U8(v) => *v as i16,
            Number::U16(v) => *v as i16,
            Number::U32(v) => *v as i16,
            Number::U64(v) => *v as i16,
            Number::U128(v) => *v as i16,
            Number::Usize(v) => *v as i16,
            Number::I8(v) => *v as i16,
            Number::I16(v) => *v,
            Number::I32(v) => *v as i16,
            Number::I64(v) => *v as i16,
            Number::I128(v) => *v as i16,
            Number::Isize(v) => *v as i16,
            Number::F32(v) => *v as i16,
            Number::F64(v) => *v as i16,
        }
    }

    pub fn as_i32(&self) -> i32 {
        match self {
            Number::U8(v) => *v as i32,
            Number::U16(v) => *v as i32,
            Number::U32(v) => *v as i32,
            Number::U64(v) => *v as i32,
            Number::U128(v) => *v as i32,
            Number::Usize(v) => *v as i32,
            Number::I8(v) => *v as i32,
            Number::I16(v) => *v as i32,
            Number::I32(v) => *v,
            Number::I64(v) => *v as i32,
            Number::I128(v) => *v as i32,
            Number::Isize(v) => *v as i32,
            Number::F32(v) => *v as i32,
            Number::F64(v) => *v as i32,
        }
    }

    pub fn as_i64(&self) -> i64 {
        match self {
            Number::U8(v) => *v as i64,
            Number::U16(v) => *v as i64,
            Number::U32(v) => *v as i64,
            Number::U64(v) => *v as i64,
            Number::U128(v) => *v as i64,
            Number::Usize(v) => *v as i64,
            Number::I8(v) => *v as i64,
            Number::I16(v) => *v as i64,
            Number::I32(v) => *v as i64,
            Number::I64(v) => *v,
            Number::I128(v) => *v as i64,
            Number::Isize(v) => *v as i64,
            Number::F32(v) => *v as i64,
            Number::F64(v) => *v as i64,
        }
    }

    pub fn as_i128(&self) -> i128 {
        match self {
            Number::U8(v) => *v as i128,
            Number::U16(v) => *v as i128,
            Number::U32(v) => *v as i128,
            Number::U64(v) => *v as i128,
            Number::U128(v) => *v as i128,
            Number::Usize(v) => *v as i128,
            Number::I8(v) => *v as i128,
            Number::I16(v) => *v as i128,
            Number::I32(v) => *v as i128,
            Number::I64(v) => *v as i128,
            Number::I128(v) => *v,
            Number::Isize(v) => *v as i128,
            Number::F32(v) => *v as i128,
            Number::F64(v) => *v as i128,
        }
    }

    pub fn as_isize(&self) -> isize {
        match self {
            Number::U8(v) => *v as isize,
            Number::U16(v) => *v as isize,
            Number::U32(v) => *v as isize,
            Number::U64(v) => *v as isize,
            Number::U128(v) => *v as isize,
            Number::Usize(v) => *v as isize,
            Number::I8(v) => *v as isize,
            Number::I16(v) => *v as isize,
            Number::I32(v) => *v as isize,
            Number::I64(v) => *v as isize,
            Number::I128(v) => *v as isize,
            Number::Isize(v) => *v,
            Number::F32(v) => *v as isize,
            Number::F64(v) => *v as isize,
        }
    }

    pub fn as_f32(&self) -> f32 {
        match self {
            Number::U8(v) => *v as f32,
            Number::U16(v) => *v as f32,
            Number::U32(v) => *v as f32,
            Number::U64(v) => *v as f32,
            Number::U128(v) => *v as f32,
            Number::Usize(v) => *v as f32,
            Number::I8(v) => *v as f32,
            Number::I16(v) => *v as f32,
            Number::I32(v) => *v as f32,
            Number::I64(v) => *v as f32,
            Number::I128(v) => *v as f32,
            Number::Isize(v) => *v as f32,
            Number::F32(v) => *v,
            Number::F64(v) => *v as f32,
        }
    }

    pub fn as_f64(&self) -> f64 {
        match self {
            Number::U8(v) => *v as f64,
            Number::U16(v) => *v as f64,
            Number::U32(v) => *v as f64,
            Number::U64(v) => *v as f64,
            Number::U128(v) => *v as f64,
            Number::Usize(v) => *v as f64,
            Number::I8(v) => *v as f64,
            Number::I16(v) => *v as f64,
            Number::I32(v) => *v as f64,
            Number::I64(v) => *v as f64,
            Number::I128(v) => *v as f64,
            Number::Isize(v) => *v as f64,
            Number::F32(v) => *v as f64,
            Number::F64(v) => *v,
        }
    }
}

impl Serialize for Number {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Number::U8(v) => serializer.serialize_u8(*v),
            Number::U16(v) => serializer.serialize_u16(*v),
            Number::U32(v) => serializer.serialize_u32(*v),
            Number::U64(v) => serializer.serialize_u64(*v),
            Number::U128(v) => serializer.serialize_u128(*v),
            Number::Usize(v) => serializer.serialize_u128(*v as u128),
            Number::I8(v) => serializer.serialize_i8(*v),
            Number::I16(v) => serializer.serialize_i16(*v),
            Number::I32(v) => serializer.serialize_i32(*v),
            Number::I64(v) => serializer.serialize_i64(*v),
            Number::I128(v) => serializer.serialize_i128(*v),
            Number::Isize(v) => serializer.serialize_i128(*v as i128),
            Number::F32(v) => serializer.serialize_f32(*v),
            Number::F64(v) => serializer.serialize_f64(*v),
        }
    }
}

impl<'de> Deserialize<'de> for Number {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        match value {
            Value::Number(number) => if number.is_f64() {
                Ok(Number::F64(number.as_f64().ok_or(serde::de::Error::custom("Invalid number"))?))
            } else if number.is_i64() {
                Ok(Number::I64(number.as_i64().ok_or(serde::de::Error::custom("Invalid number"))?))
            } else {
                Ok(Number::U64(number.as_u64().ok_or(serde::de::Error::custom("Invalid number"))?))
            }
            _ => Err(serde::de::Error::custom("not number")),
        }
    }
}


#[cfg(test)]
mod tests {
    use crate::number::Number;

    #[test]
    fn test_number() {
        let n = Number::I32(4);
        println!("{}", serde_json::to_string_pretty(&n).unwrap());
        let k: Number = serde_json::from_value(serde_json::Value::Number(serde_json::Number::from(4))).unwrap();
        println!("{}", serde_json::to_string_pretty(&k).unwrap());
    }
}