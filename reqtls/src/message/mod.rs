use crate::error::RlsResult;
pub use payload::Payload;
pub use alert::Alert;
use certificate::{CertificateStatus, Certificates};
use client_hello::ClientHello;
use key_exchange::{ClientKeyExchange, ServerKeyExchange};
use server_hello::{ServerHello, ServerHelloDone};
use session_ticket::SessionTicket;
use std::fmt::Debug;
use crate::{BufferError, CipherSuite, WriteExt};
pub use certificate::{CertificateVerify, CertificateRequest};

pub mod certificate;
pub mod client_hello;
pub mod server_hello;
pub mod key_exchange;
pub mod session_ticket;
mod payload;
mod alert;

#[derive(Debug)]
pub enum Message<'a> {
    ClientHello(ClientHello<'a>),
    ServerHello(ServerHello<'a>),
    Certificate(Certificates<'a>),
    ServerKeyExchange(ServerKeyExchange),
    ServerHelloDone(ServerHelloDone),
    ClientKeyExchange(ClientKeyExchange<'a>),
    NewSessionTicket(SessionTicket<'a>),
    Payload(Payload<'a>),
    CertificateStatus(CertificateStatus),
    CertificateRequest(CertificateRequest<'a>),
    CertificateVerify(CertificateVerify<'a>),
    Alert(Alert),
    CipherSpec,
}

impl<'a> Message<'a> {
    pub fn from_bytes(bytes: &'a mut [u8], payload: bool, suite: Option<&CipherSuite>) -> RlsResult<Message<'a>> {
        if !payload {
            let handshake_type = HandshakeType::from_byte(bytes[0]).unwrap();
            match handshake_type {
                HandshakeType::ClientHello => Ok(Message::ClientHello(ClientHello::from_bytes(handshake_type, bytes)?)),
                HandshakeType::ServerHello => Ok(Message::ServerHello(ServerHello::from_bytes(handshake_type, bytes)?)),
                HandshakeType::Certificate => Ok(Message::Certificate(Certificates::from_bytes(handshake_type, bytes)?)),
                HandshakeType::ServerKeyExchange => Ok(Message::ServerKeyExchange(ServerKeyExchange::from_bytes(handshake_type, bytes)?)),
                HandshakeType::ServerHelloDone => Ok(Message::ServerHelloDone(ServerHelloDone::from_bytes(handshake_type, bytes)?)),
                HandshakeType::ClientKeyExchange => Ok(Message::ClientKeyExchange(ClientKeyExchange::from_bytes(handshake_type, bytes, suite)?)),
                HandshakeType::NewSessionTicket => Ok(Message::NewSessionTicket(SessionTicket::from_bytes(handshake_type, bytes)?)),
                HandshakeType::CertificateStatus => Ok(Message::CertificateStatus(CertificateStatus::from_bytes(handshake_type, bytes))),
                HandshakeType::CertificateRequest => Ok(Message::CertificateRequest(CertificateRequest::from_bytes(handshake_type, bytes))),
                HandshakeType::CertificateVerify => Ok(Message::CertificateVerify(CertificateVerify::from_bytes(handshake_type, bytes))),
                HandshakeType::CipherSpec => Ok(Message::CipherSpec),
            }
        } else {
            Ok(Message::Payload(Payload::from_slice(bytes)))
        }
    }

    pub fn len(&self, key_size: u8) -> usize {
        match self {
            Message::ClientHello(v) => v.len(),
            Message::ServerHello(v) => v.len(),
            Message::Certificate(v) => v.len(),
            Message::ServerKeyExchange(v) => v.len(),
            Message::ServerHelloDone(v) => v.len(),
            Message::ClientKeyExchange(v) => v.len(key_size),
            Message::NewSessionTicket(v) => v.len(),
            Message::Payload(v) => v.value.len(),
            Message::CertificateStatus(v) => v.len(),
            Message::CertificateRequest(v) => v.len(),
            Message::CertificateVerify(v) => v.len(),
            Message::Alert(_) => 0,
            Message::CipherSpec => 1
        }
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W, key_size: u8) -> Result<(), BufferError> {
        match self {
            Message::ClientHello(v) => v.write_to(writer),
            Message::ServerHello(v) => v.write_to(writer),
            Message::Certificate(v) => v.write_to(writer),
            Message::ServerKeyExchange(v) => v.write_to(writer),
            Message::ServerHelloDone(v) => v.write_to(writer),
            Message::ClientKeyExchange(v) => v.write_to(writer, key_size),
            Message::NewSessionTicket(v) => v.write_to(writer),
            Message::Payload(v) => writer.write_slice(v.into_inner()),
            Message::CertificateStatus(v) => v.write_to(writer),
            Message::CertificateRequest(v) => v.write_to(writer),
            Message::CertificateVerify(v) => v.write_to(writer),
            Message::Alert(_) => Ok(()),
            Message::CipherSpec => writer.write_u8(1),
        }
    }

    pub fn client_mut(&mut self) -> Option<&mut ClientHello<'a>> {
        match self {
            Message::ClientHello(v) => Some(v),
            _ => None
        }
    }
    pub fn client(&self) -> Option<&ClientHello<'a>> {
        match self {
            Message::ClientHello(v) => Some(v),
            _ => None
        }
    }

    pub fn server_mut(&mut self) -> Option<&mut ServerHello<'a>> {
        match self {
            Message::ServerHello(v) => Some(v),
            _ => None
        }
    }

    pub fn server(&self) -> Option<&ServerHello<'a>> {
        match self {
            Message::ServerHello(v) => Some(v),
            _ => None
        }
    }

    // pub fn server_key_exchange(&self) -> Option<&ServerKeyExchange> {
    //     match self {
    //         Message::ServerKeyExchange(v) => Some(v),
    //         _ => None
    //     }
    // }

    pub fn client_key_exchange_mut(&mut self) -> Option<&mut ClientKeyExchange<'a>> {
        match self {
            Message::ClientKeyExchange(v) => Some(v),
            _ => None
        }
    }

    // pub fn take_payload(&mut self) -> Option<Bytes> {
    //     match self {
    //         Message::Payload(v) => Some(mem::take(v)),
    //         _ => None
    //     }
    // }

    pub fn payload(&self) -> Option<&Payload<'_>> {
        match self {
            Message::Payload(v) => Some(v),
            _ => None
        }
    }

    pub fn payload_mut(&mut self) -> Option<&'a mut Payload<'_>> {
        match self {
            Message::Payload(v) => Some(v),
            _ => None
        }
    }

    // pub fn certificate_status(&self) -> Option<&CertificateStatus> {
    //     match self {
    //         Message::CertificateStatus(v) => Some(v),
    //         _ => None
    //     }
    // }
}

#[derive(Debug, Copy, Clone)]
pub enum HandshakeType {
    ClientHello = 0x1,
    ServerHello = 0x2,
    NewSessionTicket = 0x4,
    Certificate = 0xb,
    ServerKeyExchange = 0xc,
    CertificateRequest = 0xd,
    ServerHelloDone = 0xe,
    CertificateVerify = 0xf,
    ClientKeyExchange = 0x10,
    CipherSpec = 0x14,
    CertificateStatus = 0x16,

}

impl HandshakeType {
    pub fn from_byte(byte: u8) -> Option<HandshakeType> {
        match byte {
            0x1 => Some(HandshakeType::ClientHello),
            0x2 => Some(HandshakeType::ServerHello),
            0x4 => Some(HandshakeType::NewSessionTicket),
            0xb => Some(HandshakeType::Certificate),
            0xc => Some(HandshakeType::ServerKeyExchange),
            0xd => Some(HandshakeType::CertificateRequest),
            0xe => Some(HandshakeType::ServerHelloDone),
            0xf => Some(HandshakeType::CertificateVerify),
            0x10 => Some(HandshakeType::ClientKeyExchange),
            0x14 => Some(HandshakeType::CipherSpec),
            0x16 => Some(HandshakeType::CertificateStatus),
            _ => None
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}
