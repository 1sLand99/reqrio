use std::fmt::Debug;


pub struct Payload<'a> {
    //真实payload长度，不含explicit和tag等信息
    pub(crate) value: &'a mut [u8],
}

impl<'a> Payload<'a> {

    pub fn from_slice(slice: &'a mut [u8]) -> Payload<'a> {
        Payload {
            value: slice,
        }
    }

    pub fn into_inner(self) -> &'a [u8] {
        self.value
    }
}

impl<'a> Debug for Payload<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(hex::encode(&self.value).as_str())
    }
}