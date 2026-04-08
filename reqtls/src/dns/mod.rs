mod error;
mod add;
mod query;
mod answer;
mod authoritative;

use crate::{BufferError, Reader};
use add::Additional;
use error::DNSError;
use query::DNSQuery;
use std::fmt::{Debug, Formatter};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::Range;
use crate::buffer::ReadExt;
use crate::dns::answer::DNSAnswer;
use crate::dns::authoritative::Authoritative;


pub struct Offset {
    start: usize,
    end: usize,
}

impl Offset {
    pub fn new(start: usize, end: usize) -> Offset {
        Offset { start, end }
    }

    pub fn new_end(offset: usize) -> Offset {
        Offset::new(0, offset)
    }

    pub fn take(&mut self, size: usize) -> Range<usize> {
        let res = self.start..self.start + size;
        self.add(size);
        res
    }

    pub fn add(&mut self, size: usize) {
        self.start += size;
    }

    pub fn current(&self) -> usize {
        self.start
    }

    pub fn next(&mut self) -> usize {
        let res = self.current();
        self.add(1);
        res
    }
}


struct Domain<'a>(Vec<&'a str>);

impl<'a> Domain<'a> {
    pub fn from_bytes<'b: 'a>(reader: &'b Reader<'a>) -> Result<Domain<'a>, DNSError> {
        let mut names = Vec::with_capacity(100);
        let mut pos = reader.position();
        while reader.current() != 0 {
            match reader.current() >> 6 == 0b11 {
                true => {
                    let read_pos = reader.read_u16()? as usize & 0b0011_1111_1111_1111;
                    if reader.position() - 2 == pos { pos += 2; }
                    reader.set_position(read_pos);
                    // pos += 2;
                }
                _ => {
                    let len = reader.read_u8()? as usize;
                    let item = reader.read_str::<DNSError>(len)?;
                    if reader.position() > pos {
                        pos += 1 + item.len();
                    }
                    names.push(item);
                }
            }
        }
        if reader.position() < pos {
            reader.set_position(pos);
        } else { reader.set_position(reader.position() + 1) }
        Ok(Domain(names))
    }
}
impl<'a> Debug for Domain<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        for (i, item) in self.0.iter().enumerate() {
            write!(f, "{}", item)?;
            if i < self.0.len() - 1 { write!(f, ".")? }
        }
        Ok(())
    }
}


struct DnsType(u16);

impl DnsType {
    ///Host Address
    const A: u16 = 0x0001;
    /// Authoritative name server
    const NS: u16 = 0x0002;
    ///Canonical Name
    const CNAME: u16 = 0x0005;
    ///Start of a zone of authority
    const SOA: u16 = 0x0006;
    ///Domain name PoinTeR
    const PTR: u16 = 0x000c;
    ///IPv6 Address
    const AAAA: u16 = 0x001c;
    ///
    const OPT: u16 = 0x0029;
    ///Https specific service endpoints
    const HTTPS: u16 = 0x0041;


    pub fn as_u16(&self) -> u16 {
        self.0
    }


    fn spec(&self) -> &str {
        match self.0 {
            DnsType::A => "A",
            DnsType::NS => "NS",
            DnsType::CNAME => "CNAME",
            DnsType::SOA => "SOA",
            DnsType::PTR => "PTR",
            DnsType::AAAA => "AAAA",
            DnsType::OPT => "OPT",
            DnsType::HTTPS => "HTTPS",
            _ => "Reserved"
        }
    }
}

impl Debug for DnsType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}(0x{:x})", self.spec(), self.0)
    }
}

impl From<&[u8]> for DnsType {
    fn from(bytes: &[u8]) -> Self {
        DnsType(u16::from_be_bytes([bytes[0], bytes[1]]))
    }
}

impl From<u16> for DnsType {
    fn from(value: u16) -> Self {
        DnsType(value)
    }
}

struct SvcType(u16);

impl SvcType {
    const ALPN: u16 = 0x0001;
    const IPV4: u16 = 0x0004;
    const ECHO: u16 = 0x0005;
    const IPV6: u16 = 0x0006;

    fn spec(&self) -> &str {
        match self.0 {
            SvcType::ALPN => "ALPN",
            SvcType::IPV4 => "IPv4",
            SvcType::ECHO => "Echo",
            SvcType::IPV6 => "IPv6",
            _ => "Reserved"
        }
    }
}

impl From<u16> for SvcType {
    fn from(value: u16) -> Self {
        SvcType(value)
    }
}

impl Debug for SvcType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}(0x{:x})", self.spec(), self.0)
    }
}

#[derive(Debug)]
enum SvcParamValue<'a> {
    ALPN(&'a str),
    IPV4(Ipv4Addr),
    ECHO(&'a [u8]),
    IPV6(Ipv6Addr),
}

#[derive(Debug)]
struct SvcParam<'a> {
    key: SvcType,
    len: u16,
    values: Vec<SvcParamValue<'a>>,
}

impl<'a> SvcParam<'a> {
    pub fn parsing(&self) -> usize {
        4 + self.len as usize
    }

    fn from_bytes(reader: &'a Reader<'a>) -> Result<SvcParam<'a>, DNSError> {
        let key: SvcType = reader.read_u16()?.into();
        let parse_len = reader.read_u16()?;
        let mut value_len = parse_len as usize;
        let mut values = vec![];
        println!("{:?}", key);
        while value_len > 0 {
            let value = match key.0 {
                SvcType::ALPN => {
                    let len = reader.read_u8()? as usize;
                    value_len -= 1 + len;
                    SvcParamValue::ALPN(reader.read_str::<DNSError>(len)?)
                }
                SvcType::IPV4 => {
                    value_len -= 4;
                    let slice = reader.read_slice(4)?.try_into().map_err(DNSError::SliceError)?;
                    SvcParamValue::IPV4(Ipv4Addr::from_octets(slice))
                }
                SvcType::ECHO => {
                    let slice = reader.read_slice(value_len)?;
                    value_len = 0;
                    SvcParamValue::ECHO(slice)
                }
                SvcType::IPV6 => {
                    value_len -= 16;
                    let slice = reader.read_slice(16)?.try_into().map_err(DNSError::SliceError)?;
                    SvcParamValue::IPV6(Ipv6Addr::from_octets(slice))
                }
                _ => return Err(DNSError::UnknownSvcType(key.0))
            };
            values.push(value);
        }
        Ok(SvcParam {
            key,
            len: parse_len,
            values,
        })
    }
}

#[derive(Debug)]
enum DNSValue<'a> {
    A(Ipv4Addr),
    NS(Domain<'a>),
    CName(Domain<'a>),
    SOA {
        primary_name: Domain<'a>,
        authority: Domain<'a>,
        serial_number: u32,
        refresh_interval: u32,
        retry_interval: u32,
        expire_limit: u32,
        min_ttl: u32,
    },
    AAAA(Ipv6Addr),
    OPT,
    HTTPS {
        priority: u16,
        target: Domain<'a>,
        params: Vec<SvcParam<'a>>,
    },
}

impl<'a> DNSValue<'a> {
    pub fn from_bytes(type_: &DnsType, reader: &'a Reader<'a>, len: usize) -> Result<Self, DNSError> {
        match type_.as_u16() {
            DnsType::A => Ok(DNSValue::A(Ipv4Addr::from_octets(reader.read_slice(4)?.try_into().map_err(DNSError::SliceError)?))),
            DnsType::NS => Ok(DNSValue::NS(Domain::from_bytes(reader)?)),
            DnsType::CNAME => Ok(DNSValue::CName(Domain::from_bytes(reader)?)),
            DnsType::SOA => {
                let primary_name = Domain::from_bytes(reader)?;
                let authority = Domain::from_bytes(reader)?;
                Ok(DNSValue::SOA {
                    primary_name,
                    authority,
                    serial_number: reader.read_u32()?,
                    refresh_interval: reader.read_u32()?,
                    retry_interval: reader.read_u32()?,
                    expire_limit: reader.read_u32()?,
                    min_ttl: reader.read_u32()?,
                })
            }
            DnsType::AAAA => Ok(DNSValue::AAAA(Ipv6Addr::from_octets(reader.read_slice(16)?.try_into().map_err(DNSError::SliceError)?))),
            DnsType::OPT => Ok(DNSValue::OPT),
            DnsType::HTTPS => {
                let start = reader.position();
                let priority = reader.read_u16()?;
                let target = Domain::from_bytes(reader)?;
                let mut params = vec![];
                while reader.position() < start + len {
                    println!("111={:x?}", &reader[reader.position()..]);
                    let param = SvcParam::from_bytes(reader)?;
                    params.push(param);
                }
                Ok(DNSValue::HTTPS {
                    priority,
                    target,
                    params,
                })
            }
            _ => Err(DNSError::UnknownDNSValue(type_.as_u16()))
        }
    }
}

struct ReplyCode(u8);

impl ReplyCode {
    const NO_ERROR: u8 = 0;
    const NO_SUCH_NAME: u8 = 3;

    fn spec(&self) -> &str {
        match self.0 {
            ReplyCode::NO_ERROR => "NO_ERROR",
            ReplyCode::NO_SUCH_NAME => "NO_SUCH_NAME",
            _ => "Reserved"
        }
    }
}

impl Debug for ReplyCode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}(0x{:x})", self.spec(), self.0)
    }
}

impl From<u8> for ReplyCode {
    fn from(code: u8) -> Self {
        ReplyCode(code)
    }
}


#[derive(Debug)]
struct DNSFlag {
    resp: bool,
    opcode: u8,
    authoritative: bool,
    truncated: bool,
    recursion_desired: bool,
    recursion_available: bool,
    z: bool,
    answer_authenticated: bool,
    non_authenticated: bool,
    reply_code: ReplyCode,
}

impl DNSFlag {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        DNSFlag {
            resp: bytes[0] & 0b1000_0000 == 0b1000_0000,
            opcode: bytes[0] & 0b111_1000,
            authoritative: bytes[0] & 0b100 == 0b100,
            truncated: bytes[0] & 0b10 == 0b10,
            recursion_desired: bytes[0] & 0b1 == 0b1,
            recursion_available: bytes[1] & 0b1000_0000 == 0b1000_0000,
            z: bytes[1] & 0b100_0000 == 0b100_0000,
            answer_authenticated: bytes[1] & 0b10_0000 == 0b10_0000,
            non_authenticated: bytes[1] & 0b1_0000 == 0b1_0000,
            reply_code: (bytes[1] & 0b1111).into(),
        }
    }
}

struct DNSClass(u16);

impl DNSClass {
    const IN: u16 = 0x0001;

    fn spec(&self) -> &str {
        match self.0 {
            DNSClass::IN => "IN",
            _ => "Reserved"
        }
    }
}

impl From<&[u8]> for DNSClass {
    fn from(bytes: &[u8]) -> Self {
        DNSClass(u16::from_be_bytes([bytes[0], bytes[1]]))
    }
}

impl From<u16> for DNSClass {
    fn from(code: u16) -> Self {
        DNSClass(code)
    }
}

impl Debug for DNSClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}(0x{:x})", self.spec(), self.0)
    }
}


#[derive(Debug)]
pub struct DNS<'a> {
    //transaction ID
    tid: u16,
    flag: DNSFlag,
    questions: u16,
    answer: u16,
    authority: u16,
    additional: u16,
    queries: Vec<DNSQuery<'a>>,
    answers: Vec<DNSAnswer<'a>>,
    authorities: Vec<Authoritative<'a>>,
    adds: Vec<Additional<'a>>,
}

impl<'a> DNS<'a> {
    pub fn from_bytes(reader: &'a Reader<'a>) -> Result<DNS<'a>, DNSError> {
        if reader.as_slice().len() < 12 { return Err(DNSError::Buffer(BufferError::Insufficient)); }
        let tid = reader.read_u16()?;
        let flag = DNSFlag::from_bytes(&reader[2..4]);
        reader.set_position(4);
        let questions = reader.read_u16()?;
        let answer = reader.read_u16()?;
        let authority = reader.read_u16()?;
        let additional = reader.read_u16()?;


        //query
        let mut queries = vec![];
        for _ in 0..questions {
            let query = DNSQuery::from_bytes(reader)?;
            queries.push(query);
        }

        //answer
        let mut answers = vec![];
        for _ in 0..answer {
            let answer = DNSAnswer::from_bytes(reader)?;
            answers.push(answer)
        }

        //authority
        let mut authorities = vec![];

        for _ in 0..authority {
            let authority = Authoritative::from_bytes(reader)?;
            authorities.push(authority)
        }
        //add
        let mut adds = vec![];

        for _ in 0..additional {
            // println!("222={:x?}", &reader[reader.position()..]);
            let add = Additional::from_bytes(reader)?;
            // println!("{:#?}", add);
            adds.push(add)
        }


        Ok(DNS {
            tid,
            flag,
            questions,
            answer,
            authority,
            additional,
            queries,
            answers,
            authorities,
            adds,
        })
    }
}


#[cfg(test)]
mod tests {
    use crate::dns::DNS;
    use crate::Reader;

    #[test]
    fn test_query() {
        //https
        let data = "809f012000010000000000010663727970746f0a636c6f7564666c61726503636f6d0000410001000029100000000000000c000a00081b51b2e252f509b3";
        let bytes = hex::decode(data).unwrap().into();
        let dns = DNS::from_bytes(&bytes).unwrap();
        println!("{:#?}", dns);

        //A (Host Address)
        let data = "937801000001000000000000127870617977616c6c657463646e2d70726f6409617a75726565646765036e65740000010001";
        let bytes = hex::decode(data).unwrap().into();
        let dns = DNS::from_bytes(&bytes).unwrap();
        println!("{:#?}", dns);

        //AAAA (IPv6 Address)
        let data = "717d01000001000000000000127870617977616c6c657463646e2d70726f6409617a75726565646765036e657400001c0001";
        let bytes = hex::decode(data).unwrap().into();
        let dns = DNS::from_bytes(&bytes).unwrap();
        println!("{:#?}", dns);

        //PTR
        let data = "49130100000100000000000002313903313732033136380331393207696e2d61646472046172706100000c0001";
        let bytes = hex::decode(data).unwrap().into();
        let dns = DNS::from_bytes(&bytes).unwrap();
        println!("{:#?}", dns);
    }

    #[test]
    fn test_dns() {
        let data = "fcd98180000100020001000002636e0462696e6703636f6d0000410001c00c0005000100000258002709636e62696e672d636e0462696e6703636f6d0e747261666669636d616e61676572036e657400c02900050001000002580013056368696e610762696e6731323303636f6d00c0620006000100000020004d066e73312d303409617a7572652d646e7303636f6d0013617a757265646e732d686f73746d6173746572096d6963726f736f667403636f6d000000000100000e100000012c0024ea000000012c";
        let bytes = hex::decode(data).unwrap().into();
        let dns = DNS::from_bytes(&bytes).unwrap();
        println!("{:#?}", dns);

        let data = "eb1481800001000a000200070b6c66332d63646e2d746f73076279746573636d03636f6d0000010001c00c000500010000025800290b6c66332d63646e2d746f73076279746573636d03636f6d017709616c696b756e6c756e03636f6d00c035000500010000025800260b6c66332d63646e2d746f73076279746573636d03636f6d087175656e6975756603636f6d00c06a000100010000025800047ce10e2bc06a000100010000025800047ce10e2dc06a000100010000025800047ce10e2ec06a000100010000025800047ce10e2cc06a000100010000025800047ce10e2fc06a000100010000025800047ce10e2ac06a000100010000025800047ce10e31c06a00010001000002580004b703cd0b087175656e6975756603636f6d00000200010000019f0016067669706e7334097175656e6975646e7303636f6d00c110000200010000019f0016067669706e7334097175656e6975646e73036e657400c12800010001000001ee000408842278c12800010001000001ee0004088ff1f9c12800010001000001ee00042f768ab8c14a000100010000005e000408898ecbc14a000100010000005e0004089327b8c14a000100010000005e00042f78e238c128001c0001000001ee00102408400a101000000000000000001111";
        let bytes = hex::decode(data).unwrap().into();
        let dns = DNS::from_bytes(&bytes).unwrap();
        println!("{:#?}", dns);

        let data = "5867818000010001000500150663727970746f0a636c6f7564666c61726503636f6d0000410001c00c004100010000025800850001000001000302683200040008a29f874fa29f884f000500470045fe0d00414100200020901a4dfdb98bc0fd103a31dfe1bb4e5a7822ebc5ef49351ce4bd9469e7b1ce630004000100010012636c6f7564666c6172652d6563682e636f6d000000060020260647000007000000000000a29f874f260647000007000000000000a29f884fc01300020001000002010006036e7335c013c01300020001000002010006036e7333c013c01300020001000002010006036e7334c013c01300020001000002010006036e7336c013c01300020001000002010006036e7337c013c0d6000100010000008f0004a29f0021c0d6000100010000008f0004a29f07e2c0c400010001000001270004a29f0209c0c400010001000001270004a29f0937c0e8000100010000005b0004a29f0121c0e8000100010000005b0004a29f0837c0fa00010001000001e00004a29f030bc0fa00010001000001e00004a29f0506c10c00010001000000d70004a29f0408c10c00010001000000d70004a29f0606c0d6001c0001000001df00102400cb002049000100000000a29f0021c0d6001c0001000001df00102400cb002049000100000000a29f07e2c0c4001c00010000012700102400cb002049000100000000a29f0209c0c4001c00010000012700102400cb002049000100000000a29f0937c0e8001c00010000005b00102400cb002049000100000000a29f0121c0e8001c00010000005b00102400cb002049000100000000a29f0837c0fa001c0001000001df00102400cb002049000100000000a29f030bc0fa001c0001000001df00102400cb002049000100000000a29f0506c10c001c0001000000d700102400cb002049000100000000a29f0408c10c001c0001000000d700102400cb002049000100000000a29f060600002904d0000000000000";
        let bytes = hex::decode(data).unwrap().into();
        let dns = DNS::from_bytes(&bytes).unwrap();
        println!("{:#?}", dns);
    }
}