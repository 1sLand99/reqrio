use crate::error::RlsResult;
use crate::WriteExt;
use super::super::bytes::Bytes;
use super::super::message::HandshakeType;

#[derive(Debug)]
pub struct TlsSessionTicket {
    lifetime: u32,
    len: u16,
    value: Bytes,
}

impl TlsSessionTicket {
    pub fn new() -> TlsSessionTicket {
        TlsSessionTicket {
            lifetime: 3600,
            len: 0,
            value: Bytes::none(),
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> RlsResult<TlsSessionTicket> {
        let mut res = TlsSessionTicket::new();
        res.lifetime = u32::from_be_bytes(bytes[0..4].try_into()?);
        res.len = u16::from_be_bytes(bytes[4..6].try_into()?);
        res.value = Bytes::new(bytes[6..6 + res.len as usize].to_vec());
        Ok(res)
    }

    pub fn len(&self) -> usize {
        6 + self.value.len()
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) {
        writer.write_u32(self.lifetime);
        writer.write_u16(self.value.len() as u16);
        writer.write_slice(self.value.as_ref());
    }

    pub fn set_value(&mut self, value: Vec<u8>) {
        self.value = Bytes::new(value);
    }
}

#[derive(Debug)]
pub struct SessionTicket {
    handshake_type: HandshakeType,
    len: u32,
    tls_ticket: TlsSessionTicket,
}

impl SessionTicket {
    pub fn new() -> SessionTicket {
        SessionTicket {
            handshake_type: HandshakeType::NewSessionTicket,
            len: 0,
            tls_ticket: TlsSessionTicket::new(),
        }
    }

    pub fn from_bytes(ht: HandshakeType, bytes: &[u8]) -> RlsResult<SessionTicket> {
        let mut res = SessionTicket::new();
        res.handshake_type = ht;
        res.len = u32::from_be_bytes([0, bytes[1], bytes[2], bytes[3]]);
        res.tls_ticket = TlsSessionTicket::from_bytes(&bytes[4..])?;
        Ok(res)
    }

    pub fn len(&self) -> usize {
        4 + self.tls_ticket.len()
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) {
        writer.write_u8(self.handshake_type as u8);
        writer.write_slice(&(self.tls_ticket.len() as u32).to_be_bytes()[1..]);
        self.tls_ticket.write_to(writer);
    }
    
    pub fn tls_ticket_mut(&mut self) -> &mut TlsSessionTicket {
        &mut self.tls_ticket
    }
}