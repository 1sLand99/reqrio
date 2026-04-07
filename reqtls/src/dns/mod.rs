mod error;
mod add;
mod query;

use crate::BufferError;
use error::DNSError;
use std::fmt::Debug;
use add::Additional;
use query::DNSQuery;

#[derive(Debug)]
struct DNSFlag {
    resp: bool,
    opcode: u8,
    truncated: bool,
    recursion: bool,
    z: bool,
    ad: bool,
    auth: bool,
}

impl DNSFlag {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        DNSFlag {
            resp: bytes[0] & 0b1000_0000 == 0b1000_0000,
            opcode: bytes[0] & 0b111_1000,
            truncated: bytes[0] & 0b10 == 0b10,
            recursion: bytes[0] & 0b1 == 0b1,
            z: bytes[1] & 0b100_0000 == 0b100_0000,
            ad: bytes[1] & 0b10_0000 == 0b10_0000,
            auth: bytes[1] & 0b1_0000 == 0b1_0000,
        }
    }
}


#[derive(Debug)]
pub struct DNS {
    //transaction ID
    tid: u16,
    flag: DNSFlag,
    questions: u16,
    answers: u16,
    authority: u16,
    additional: u16,
    queries: Vec<DNSQuery>,
    adds: Vec<Additional>,
}

impl DNS {
    pub fn from_bytes(bytes: &[u8]) -> Result<DNS, DNSError> {
        if bytes.len() < 12 { return Err(DNSError::Buffer(BufferError::Insufficient)); }
        let questions = u16::from_be_bytes([bytes[4], bytes[5]]);
        let mut queries = vec![];
        let mut index = 12;
        for _ in 0..questions {
            let query = DNSQuery::from_bytes(&bytes[index..])?;
            index += query.len();
            queries.push(query);
        }
        let mut adds = vec![];
        let additional = u16::from_be_bytes([bytes[10], bytes[11]]);
        for _ in 0..additional {
            let add = Additional::from_bytes(&bytes[index..])?;
            adds.push(add)
        }


        Ok(DNS {
            tid: u16::from_be_bytes([bytes[0], bytes[1]]),
            flag: DNSFlag::from_bytes(&bytes[2..4]),
            questions,
            answers: u16::from_be_bytes([bytes[6], bytes[7]]),
            authority: u16::from_be_bytes([bytes[8], bytes[9]]),
            additional: u16::from_be_bytes([bytes[10], bytes[11]]),
            queries,
            adds,
        })
    }
}


#[cfg(test)]
mod tests {
    use crate::dns::DNS;

    #[test]
    fn test_dns() {
        let data = "809f012000010000000000010663727970746f0a636c6f7564666c61726503636f6d0000410001000029100000000000000c000a00081b51b2e252f509b3";
        let bytes = hex::decode(data).unwrap();
        let dns = DNS::from_bytes(&bytes).unwrap();
        println!("{:#?}", dns)
    }
}