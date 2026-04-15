use super::super::boring::SignatureAlgorithm;
use super::super::message::HandshakeType;
use crate::buffer::Buf;
use crate::error::RlsResult;
use crate::{u24, BufferError, CipherSuite, ReadExt, Reader, WriteExt};
use std::fmt::{Debug, Formatter};

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

#[derive(Copy, Clone)]
pub struct NamedCurve(u16);

#[allow(non_upper_case_globals)]
impl NamedCurve {
    pub const X25519: u16 = 0x1d;
    pub const X25519MLKEM768: u16 = 0x11ec;
    pub const Secp256r1: u16 = 0x0017;
    pub const Secp384r1: u16 = 0x0018;
    pub const Secp521r1: u16 = 0x0019;

    fn spec(&self) -> &str {
        match self.0 {
            NamedCurve::X25519 => "X25519",
            NamedCurve::X25519MLKEM768 => "X25519MLKEM768",
            NamedCurve::Secp256r1 => "Secp256r1",
            NamedCurve::Secp384r1 => "Secp384r1",
            NamedCurve::Secp521r1 => "Secp521r1",
            _ => "Reserved"
        }
    }

    pub fn new(v: u16) -> NamedCurve {
        NamedCurve(v)
    }

    pub fn into_inner(self) -> u16 { self.0 }

    pub fn as_u16(&self) -> u16 {
        self.0
    }

    pub fn is_reserved(&self) -> bool {
        !matches!(self.0, 0x1d | 0x11ec | 0x0017 | 0x0018 | 0x0019)
    }

    pub fn secret_index(&self) -> RlsResult<usize> {
        match self.0 {
            NamedCurve::X25519 => Ok(0),
            NamedCurve::Secp256r1 => Ok(1),
            NamedCurve::Secp384r1 => Ok(2),
            NamedCurve::Secp521r1 => Ok(3),
            _ => Err("Unsupported pub share key".into()),
        }
    }
}

impl From<u16> for NamedCurve {
    fn from(v: u16) -> Self { NamedCurve(v) }
}

impl Debug for NamedCurve {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}(0x{:x})", self.spec(), self.0)
    }
}

impl PartialEq<u16> for NamedCurve {
    fn eq(&self, other: &u16) -> bool {
        &self.0 == other
    }
}


#[derive(Debug)]
pub struct ServerHellmanParam<'a> {
    curve_type: CurveType,
    named_curve: NamedCurve,
    pub_key_len: u8,
    pub_key: Buf<'a>,
    signature_algorithm: SignatureAlgorithm,
    signature_len: u16,
    signature: Buf<'a>,
}

impl<'a> ServerHellmanParam<'a> {
    pub fn new() -> ServerHellmanParam<'a> {
        ServerHellmanParam {
            curve_type: CurveType::NamedCurve,
            named_curve: NamedCurve::Secp384r1.into(),
            pub_key_len: 0,
            pub_key: Buf::Ref(&[]),
            signature_algorithm: SignatureAlgorithm::RSA_PSS_RSAE_SHA256.into(),
            signature_len: 0,
            signature: Buf::Ref(&[]),
        }
    }
    pub fn from_reader(reader: &mut Reader<'a>) -> RlsResult<ServerHellmanParam<'a>> {
        let mut res = ServerHellmanParam::new();
        res.curve_type = CurveType::from_u8(reader.read_u8()?).ok_or("CurveType Unknown")?;
        res.named_curve = NamedCurve::new(reader.read_u16()?);
        res.pub_key_len = reader.read_u8()?;
        res.pub_key = Buf::Ref(reader.read_slice(res.pub_key_len as usize)?);
        res.signature_algorithm = SignatureAlgorithm::new(reader.read_u16()?);
        res.signature_len = reader.read_u16()?;
        res.signature = Buf::Ref(reader.read_slice(res.signature_len as usize)?);
        Ok(res)
    }

    pub fn len(&self) -> usize {
        8 + self.pub_key.len() + self.signature.len()
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) -> Result<(), BufferError> {
        writer.write_u8(self.curve_type as u8)?;
        writer.write_u16(self.named_curve.0)?;
        writer.write_u8(self.pub_key.len() as u8)?;
        writer.write_slice(self.pub_key.as_ref())?;
        writer.write_u16(self.signature_algorithm.into_inner())?;
        writer.write_u16(self.signature.len() as u16)?;
        writer.write_slice(self.signature.as_ref())
    }

    pub fn curve_type(&self) -> &CurveType { &self.curve_type }

    pub fn pub_key(&self) -> &Buf<'a> {
        &self.pub_key
    }

    pub fn named_curve(&self) -> &NamedCurve {
        &self.named_curve
    }

    pub fn signature(&self) -> &Buf<'a> {
        &self.signature
    }

    pub fn signature_algorithm(&self) -> &SignatureAlgorithm {
        &self.signature_algorithm
    }

    pub fn set_pub_key(&mut self, pub_key: Buf<'a>) {
        self.pub_key = pub_key;
    }

    pub fn set_signature(&mut self, signature: Buf<'a>) {
        self.signature = signature;
    }
}

#[derive(Debug)]
pub struct ServerKeyExchange<'a> {
    handshake_type: HandshakeType,
    hellman_param: ServerHellmanParam<'a>,
}

impl<'a> Default for ServerKeyExchange<'a> {
    fn default() -> Self {
        ServerKeyExchange {
            handshake_type: HandshakeType::ServerKeyExchange,
            hellman_param: ServerHellmanParam::new(),
        }
    }
}

impl<'a> ServerKeyExchange<'a> {
    pub fn from_reader(ht: HandshakeType, reader: &mut Reader<'a>) -> RlsResult<ServerKeyExchange<'a>> {
        reader.read_24()?;
        Ok(ServerKeyExchange {
            handshake_type: ht,
            hellman_param: ServerHellmanParam::from_reader(reader)?,
        })
    }

    pub fn is_empty(&self) -> bool { self.len() == 0 }

    pub fn len(&self) -> usize {
        4 + self.hellman_param.len()
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) -> Result<(), BufferError> {
        writer.write_u8(self.handshake_type as u8)?;
        writer.write_u24(self.hellman_param.len() as u24)?;
        self.hellman_param.write_to(writer)
    }

    pub fn hellman_param(&self) -> &ServerHellmanParam<'a> {
        &self.hellman_param
    }

    pub fn hellman_param_mut(&mut self) -> &mut ServerHellmanParam<'a> { &mut self.hellman_param }
}

#[derive(Debug)]
pub struct ClientHellmanParam<'a> {
    pub_key_len: u16,
    pub_key: Buf<'a>,
}

impl<'a> ClientHellmanParam<'a> {
    pub fn new() -> ClientHellmanParam<'a> {
        ClientHellmanParam {
            pub_key_len: 0,
            pub_key: Buf::Ref(&[]),
        }
    }

    pub fn from_reader(reader: &mut Reader<'a>, suite: Option<&CipherSuite>) -> RlsResult<ClientHellmanParam<'a>> {
        let mut res = ClientHellmanParam::new();
        let key_size = suite.map(|x| x.key_size()).unwrap_or(1);
        res.pub_key_len = if key_size == 2 { reader.read_u16()? } else { reader.read_u8()? as u16 };
        res.pub_key = Buf::Ref(reader.read_slice(res.pub_key_len as usize)?);
        Ok(res)
    }
    pub fn len(&self, key_size: u8) -> usize {
        key_size as usize + self.pub_key.len()
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W, key_size: u8) -> Result<(), BufferError> {
        match key_size {
            2 => writer.write_u16(self.pub_key.len() as u16)?,
            _ => writer.write_u8(self.pub_key.len() as u8)?,
        }
        writer.write_slice(self.pub_key.as_ref())
    }

    pub fn pub_key(&self) -> &Buf<'a> {
        &self.pub_key
    }
}

#[derive(Debug)]
pub struct ClientKeyExchange<'a> {
    handshake_type: HandshakeType,
    hellman_param: ClientHellmanParam<'a>,
}

impl<'a> Default for ClientKeyExchange<'a> {
    fn default() -> Self {
        ClientKeyExchange {
            handshake_type: HandshakeType::ClientHello,
            hellman_param: ClientHellmanParam::new(),
        }
    }
}

impl<'a> ClientKeyExchange<'a> {
    pub fn from_reader(ht: HandshakeType, reader: &mut Reader<'a>, suite: Option<&CipherSuite>) -> RlsResult<ClientKeyExchange<'a>> {
        reader.read_24()?;
        Ok(ClientKeyExchange {
            handshake_type: ht,
            hellman_param: ClientHellmanParam::from_reader(reader, suite)?,
        })
    }

    pub fn len(&self, key_size: u8) -> usize {
        4 + self.hellman_param.len(key_size)
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W, key_size: u8) -> Result<(), BufferError> {
        writer.write_u8(self.handshake_type as u8)?;
        writer.write_u24(self.hellman_param.len(key_size) as u24)?;
        self.hellman_param.write_to(writer, key_size)
    }

    pub fn set_pub_key(&mut self, pub_key: &'a [u8]) {
        self.hellman_param.pub_key = Buf::Ref(pub_key);
        self.hellman_param.pub_key_len = self.hellman_param.pub_key.len() as u16;
    }

    pub fn hellman_param(&self) -> &ClientHellmanParam<'a> {
        &self.hellman_param
    }
}

