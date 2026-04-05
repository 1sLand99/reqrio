use super::super::message::HandshakeType;
use crate::buffer::Buf;
use crate::error::RlsResult;
use crate::{BufferError, WriteExt};

#[derive(Debug)]
pub struct TlsSessionTicket<'a> {
    lifetime: u32,
    value: Buf<'a>,
}

impl<'a> Default for TlsSessionTicket<'a> {
    fn default() -> TlsSessionTicket<'a> {
        TlsSessionTicket {
            lifetime: 3600,
            value: Buf::Ref(&[]),
        }
    }
}

impl<'a> TlsSessionTicket<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> RlsResult<TlsSessionTicket<'a>> {
        let len = u16::from_be_bytes(bytes[4..6].try_into()?) as usize;
        Ok(TlsSessionTicket {
            lifetime: u32::from_be_bytes(bytes[0..4].try_into()?),
            value: Buf::Ref(&bytes[6..6 + len as usize]),
        })
    }

    pub fn is_empty(&self) -> bool { self.len() == 0 }

    pub fn len(&self) -> usize {
        6 + self.value.len()
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W)-> Result<(), BufferError> {
        writer.write_u32(self.lifetime, false)?;
        writer.write_u16(self.value.len() as u16)?;
        writer.write_slice(self.value.as_ref())
    }

    pub fn set_value(&mut self, value: &'a [u8]) {
        self.value = Buf::Ref(value);
    }
}

#[derive(Debug)]
pub struct SessionTicket<'a> {
    handshake_type: HandshakeType,
    tls_ticket: TlsSessionTicket<'a>,
}

impl<'a> Default for SessionTicket<'a> {
    fn default() -> SessionTicket<'a> {
        SessionTicket {
            handshake_type: HandshakeType::NewSessionTicket,
            tls_ticket: TlsSessionTicket::default(),
        }
    }
}

impl<'a> SessionTicket<'a> {
    pub fn from_bytes(ht: HandshakeType, bytes: &'a [u8]) -> RlsResult<SessionTicket<'a>> {
        let len = u32::from_be_bytes([0, bytes[1], bytes[2], bytes[3]]) as usize;
        Ok(SessionTicket {
            handshake_type: ht,
            tls_ticket: TlsSessionTicket::from_bytes(&bytes[4..4 + len])?,
        })
    }

    pub fn is_empty(&self) -> bool { self.len() == 0 }

    pub fn len(&self) -> usize {
        4 + self.tls_ticket.len()
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) -> Result<(), BufferError> {
        writer.write_u8(self.handshake_type as u8)?;
        writer.write_u32(self.tls_ticket.len() as u32, true)?;
        self.tls_ticket.write_to(writer)
    }

    pub fn tls_ticket_mut(&mut self) -> &mut TlsSessionTicket<'a> {
        &mut self.tls_ticket
    }
}