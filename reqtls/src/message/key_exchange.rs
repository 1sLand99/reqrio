use crate::CipherSuite;
use crate::error::RlsResult;
use super::super::boring::SignatureAlgorithm;
use super::super::message::HandshakeType;
use super::super::bytes::Bytes;

#[derive(Debug, Copy, Clone)]
pub enum CurveType {
    NamedCurve = 0x3
}

impl CurveType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x3 => Some(Self::NamedCurve),
            _ => None
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
pub enum NamedCurve {
    x25519 = 0x1d,
    Secp256r1 = 0x17,
    Secp384r1 = 0x18,
    Secp521r1 = 0x19,
}

impl NamedCurve {
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            0x1d => Some(Self::x25519),
            0x17 => Some(Self::Secp256r1),
            0x18 => Some(Self::Secp384r1),
            0x19 => Some(Self::Secp521r1),
            _ => None
        }
    }
    pub fn as_bytes(&self) -> [u8; 2] {
        (*self as u16).to_be_bytes()
    }
}

#[derive(Debug)]
pub struct ServerHellmanParam {
    curve_type: CurveType,
    named_curve: NamedCurve,
    pub_key_len: u8,
    pub_key: Bytes,
    signature_algorithm: SignatureAlgorithm,
    signature_len: u16,
    signature: Bytes,
}

impl ServerHellmanParam {
    pub fn new() -> ServerHellmanParam {
        ServerHellmanParam {
            curve_type: CurveType::NamedCurve,
            named_curve: NamedCurve::Secp384r1,
            pub_key_len: 0,
            pub_key: Bytes::none(),
            signature_algorithm: SignatureAlgorithm::RSA_PSS_RSAE_SHA256,
            signature_len: 0,
            signature: Bytes::none(),
        }
    }
    pub fn from_bytes(bytes: &[u8]) -> RlsResult<ServerHellmanParam> {
        let mut res = ServerHellmanParam::new();
        res.curve_type = CurveType::from_u8(bytes[0]).ok_or("CurveType Unknown")?;
        let v = u16::from_be_bytes([bytes[1], bytes[2]]);
        res.named_curve = NamedCurve::from_u16(v).ok_or(format!("NamedCurve Unknown-{}", v))?;
        res.pub_key_len = bytes[3];
        res.pub_key = Bytes::new(bytes[4..res.pub_key_len as usize + 4].to_vec());
        let index = res.pub_key_len as usize + 4;
        let v = u16::from_be_bytes([bytes[index], bytes[index + 1]]);
        res.signature_algorithm = SignatureAlgorithm::from_u16(v).ok_or("SignatureAlgorithm Unknown")?;
        res.signature_len = u16::from_be_bytes([bytes[index + 2], bytes[index + 3]]);
        res.signature = Bytes::new(bytes[index + 4..index + 4 + res.signature_len as usize].to_vec());
        Ok(res)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut res = vec![self.curve_type.as_u8()];
        res.extend(self.named_curve.as_bytes());
        res.push(self.pub_key.len() as u8);
        res.extend(self.pub_key.as_bytes());
        res.extend(self.signature_algorithm.as_bytes());
        res.extend((self.signature.len() as u16).to_be_bytes());
        res.extend(self.signature.as_bytes());
        res
    }

    pub fn curve_type(&self) -> &CurveType { &self.curve_type }

    pub fn pub_key(&self) -> &Bytes {
        &self.pub_key
    }

    pub fn named_curve(&self) -> &NamedCurve {
        &self.named_curve
    }

    pub fn signature(&self) -> &Bytes {
        &self.signature
    }

    pub fn signature_algorithm(&self) -> SignatureAlgorithm {
        self.signature_algorithm
    }

    pub fn set_pub_key(&mut self, pub_key: impl Into<Vec<u8>>) {
        self.pub_key = Bytes::new(pub_key.into());
    }

    pub fn set_signature(&mut self, signature: Bytes) {
        self.signature = signature;
    }
}

#[derive(Debug)]
pub struct ServerKeyExchange {
    handshake_type: HandshakeType,
    len: u32,
    hellman_param: ServerHellmanParam,
}

impl Default for ServerKeyExchange {
    fn default() -> Self {
        ServerKeyExchange {
            handshake_type: HandshakeType::ServerKeyExchange,
            len: 0,
            hellman_param: ServerHellmanParam::new(),
        }
    }
}

impl ServerKeyExchange {
    pub fn from_bytes(ht: HandshakeType, bytes: &[u8]) -> RlsResult<ServerKeyExchange> {
        let mut res = ServerKeyExchange::default();
        res.handshake_type = ht;
        res.len = u32::from_be_bytes([0, bytes[1], bytes[2], bytes[3]].try_into()?);
        res.hellman_param = ServerHellmanParam::from_bytes(&bytes[4..])?;
        Ok(res)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut res = vec![self.handshake_type.as_u8()];
        let vbs = self.hellman_param.as_bytes();
        res.extend_from_slice(&(vbs.len() as u32).to_be_bytes()[1..]);
        res.extend(vbs);
        res
    }

    pub fn hellman_param(&self) -> &ServerHellmanParam {
        &self.hellman_param
    }

    pub fn hellman_param_mut(&mut self) -> &mut ServerHellmanParam { &mut self.hellman_param }

    pub fn len(&self) -> u32 {
        self.len
    }
}

#[derive(Debug)]
pub struct ClientHellmanParam {
    pub_key_len: u16,
    pub_key: Bytes,
}

impl ClientHellmanParam {
    pub fn new() -> ClientHellmanParam {
        ClientHellmanParam {
            pub_key_len: 0,
            pub_key: Bytes::new(vec![]),
        }
    }

    pub fn from_bytes(bytes: &[u8], suite: Option<&CipherSuite>) -> RlsResult<ClientHellmanParam> {
        let mut res = ClientHellmanParam::new();
        let key_size = suite.map(|x|x.key_size()).unwrap_or(1);
        res.pub_key_len = if key_size == 2 { u16::from_be_bytes([bytes[0], bytes[1]]) } else { bytes[0] as u16 };
        res.pub_key = Bytes::new(bytes[key_size as usize..res.pub_key_len as usize + key_size as usize].to_vec());
        Ok(res)
    }

    pub fn as_bytes(&self, suite: &CipherSuite) -> Vec<u8> {
        let mut res = if suite.key_size() == 2 { (self.pub_key.len() as u16).to_be_bytes().to_vec() } else { vec![self.pub_key.len() as u8] };
        res.extend(self.pub_key.as_bytes());
        res
    }

    pub fn pub_key(&self) -> &Bytes {
        &self.pub_key
    }
}

#[derive(Debug)]
pub struct ClientKeyExchange {
    handshake_type: HandshakeType,
    len: u32,
    hellman_param: ClientHellmanParam,
}

impl Default for ClientKeyExchange {
    fn default() -> Self {
        ClientKeyExchange {
            handshake_type: HandshakeType::ClientHello,
            len: 0,
            hellman_param: ClientHellmanParam::new(),
        }
    }
}

impl ClientKeyExchange {
    pub fn from_bytes(ht: HandshakeType, bytes: &[u8], suite: Option<&CipherSuite>) -> RlsResult<ClientKeyExchange> {
        let mut res = ClientKeyExchange::default();
        res.handshake_type = ht;
        res.len = u32::from_be_bytes([0, bytes[1], bytes[2], bytes[3]].try_into()?);
        res.hellman_param = ClientHellmanParam::from_bytes(&bytes[4..], suite)?;
        Ok(res)
    }

    pub fn as_bytes(&self, suite: &CipherSuite) -> Vec<u8> {
        let mut res = vec![self.handshake_type.as_u8()];
        let vbs = self.hellman_param.as_bytes(suite);
        res.extend_from_slice(&(vbs.len() as u32).to_be_bytes()[1..]);
        res.extend(vbs);
        res
    }

    pub fn set_pub_key(&mut self, pub_key: impl Into<Vec<u8>>) {
        self.hellman_param.pub_key = Bytes::new(pub_key.into());
        self.hellman_param.pub_key_len = self.hellman_param.pub_key.len() as u16;
    }

    pub fn len(&self) -> u32 {
        self.len
    }

    pub fn hellman_param(&self) -> &ClientHellmanParam {
        &self.hellman_param
    }
}

