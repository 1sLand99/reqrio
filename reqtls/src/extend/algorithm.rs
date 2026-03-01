use crate::boring::SignatureAlgorithm;
use crate::error::RlsResult;
use crate::{rand, WriteExt};


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

    pub fn len(&self) -> usize {
        self.hash.len() * 2 + 2
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) {
        writer.write_u16(self.len() as u16 - 2);
        for hash in self.hash {
            writer.write_u16(hash.into_inner());
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> RlsResult<SignatureAlgorithms> {
        let mut res = SignatureAlgorithms::new();
        res.hash_len = u16::from_be_bytes([bytes[0], bytes[1]]);
        for chunk in bytes[2..].chunks(2) {
            let v = u16::from_be_bytes(chunk.try_into()?);
            res.hash.push(SignatureAlgorithm::new(v));
        }
        Ok(res)
    }

    pub fn hashes(&self) -> &Vec<SignatureAlgorithm> {
        &self.hash
    }

    pub fn set_hashes(&mut self, hashes: Vec<SignatureAlgorithm>) {
        self.hash = hashes;
    }

    pub fn push_hash(&mut self, hash: SignatureAlgorithm) {
        self.hash.push(hash);
    }

    pub fn clear(&mut self) {
        self.hash.clear();
    }

    pub fn random() -> SignatureAlgorithms {
        let mut res = SignatureAlgorithms::new();
        let all_sign = SignatureAlgorithm::ALL;
        res.hash = vec![
            SignatureAlgorithm::RSA_PSS_RSAE_SHA256,
            SignatureAlgorithm::ECDSA_SECP256R1_SHA256,
            SignatureAlgorithm::RSA_PKCS1_SHA256,
        ];
        while res.hash.len() < 10 {
            let index = rand::random::<usize>() % all_sign.len();
            if res.hash.contains(&SignatureAlgorithm::new(all_sign[index])) { continue; }
            res.hash.push(SignatureAlgorithm::new(all_sign[index]));
        }
        res
    }
}

