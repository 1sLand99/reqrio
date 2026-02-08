use crate::boring::SignatureAlgorithm;
use crate::error::RlsResult;
use crate::rand;


#[derive(Debug)]
pub struct SignatureAlgorithms {
    hash_len: u16,
    hash: Vec<SignatureAlgorithm>,
}

impl SignatureAlgorithms {
    pub fn new() -> SignatureAlgorithms {
        SignatureAlgorithms {
            hash_len: 0,
            hash: vec![],
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> RlsResult<SignatureAlgorithms> {
        let mut res = SignatureAlgorithms::new();
        res.hash_len = u16::from_be_bytes([bytes[0], bytes[1]]);
        for chunk in bytes[2..].chunks(2) {
            let v = u16::from_be_bytes(chunk.try_into()?);
            res.hash.push(SignatureAlgorithm::from_u16(v).ok_or(format!("SignatureAlgorithm Unknown-{}", v))?);
        }
        Ok(res)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut res = vec![0, 0];
        for hash in &self.hash {
            res.extend(hash.as_bytes());
        }
        let len = (res.len() - 2) as u16;
        res[0..2].copy_from_slice(len.to_be_bytes().as_ref());
        res
    }

    pub fn hashes(&self) -> &Vec<SignatureAlgorithm> {
        &self.hash
    }

    pub fn push_hash(&mut self, hash: SignatureAlgorithm) {
        self.hash.push(hash);
    }

    pub fn clear(&mut self) {
        self.hash.clear();
    }

    pub fn random() -> SignatureAlgorithms {
        let mut res = SignatureAlgorithms::new();
        let all_sign = SignatureAlgorithm::all();
        while res.hash.len() < 10 {
            let index = rand::random::<usize>() % all_sign.len();
            if res.hash.contains(&all_sign[index]) { continue; }
            res.hash.push(all_sign[index]);
        }
        res
    }
}

