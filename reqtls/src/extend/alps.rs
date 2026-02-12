use crate::ALPN;
use crate::error::RlsResult;


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

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut res = vec![0, 0];
        for value in &self.values {
            res.extend(value.as_bytes());
        }
        let len = (res.len() - 2) as u16;
        res[0..2].clone_from_slice(len.to_be_bytes().as_slice());
        res
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