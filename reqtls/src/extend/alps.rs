use crate::error::RlsResult;
use crate::{WriteExt, ALPN};


#[derive(Debug)]
pub struct ALPS {
    len: u16,
    values: Vec<ALPN>,
}

impl ALPS {
    pub fn new() -> ALPS {
        ALPS {
            len: 0,
            values: vec![],
        }
    }
    pub fn from_bytes(bytes: &[u8]) -> RlsResult<ALPS> {
        let mut res = ALPS::new();
        res.len = u16::from_be_bytes([bytes[0], bytes[1]]);
        res.values = ALPN::from_bytes(&bytes[2..res.len as usize + 2])?;
        Ok(res)
    }

    pub fn len(&self) -> usize {
        self.values.iter().map(|x| x.len()).sum::<usize>() + 2
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) {
        writer.write_u16(self.len() as u16 - 2);
        for value in self.values {
            value.write_to(writer);
        }
    }

    pub fn remove_h2_alpn(&mut self) {
        if self.values.len() <= 1 {
            self.values = vec![ALPN::Http11]
        } else {
            self.values = self.values.clone().into_iter().filter(|x| x != &ALPN::Http20).collect();
        }
    }

    pub fn add_h2_alpn(&mut self) {
        self.values.clear();
        self.values = vec![
            ALPN::Http20,
            ALPN::Http11,
        ]
    }

    pub fn add_alpn(&mut self, alpn: ALPN) {
        self.values.push(alpn);
    }

    pub fn values(&self) -> &Vec<ALPN> {
        &self.values
    }
}