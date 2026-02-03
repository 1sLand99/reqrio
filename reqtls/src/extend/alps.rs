use crate::error::RlsResult;
#[derive(Debug, PartialEq, Clone)]
pub enum ALPN {
    Http20,
    Http11,
    Http10,
    None,
}

impl ALPN {
    pub fn from_slice(opt: &[u8]) -> ALPN {
        match opt {
            b"http/1.0" => ALPN::Http10,
            b"http/1.1" => ALPN::Http11,
            b"h2" => ALPN::Http20,
            _ => {
                println!("unknown alpn {:?}", opt);
                ALPN::None
            }
        }
    }

    pub fn value(&self) -> &'static str {
        match self {
            ALPN::Http10 => "http/1.0",
            ALPN::Http11 => "http/1.1",
            ALPN::Http20 => "h2",
            ALPN::None => ""
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> RlsResult<Vec<ALPN>> {
        let mut res = vec![];
        let mut index = 0;
        while index < bytes.len() {
            let len = bytes[index] as usize;
            res.push(ALPN::from_slice(&bytes[index + 1..len + index + 1]));
            index = index + 1 + len;
        }
        Ok(res)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut res = self.value().as_bytes().to_vec();
        res.insert(0, res.len() as u8);
        res
    }
}

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