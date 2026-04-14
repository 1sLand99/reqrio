mod certificate;
mod client_hello;
mod server_hello;
mod key_exchange;
mod session_ticket;
mod payload;
mod alert;
mod encrypted_extension;

use crate::error::RlsResult;
pub use payload::Payload;
pub use alert::Alert;
pub use certificate::Certificates;
use certificate::CertificateStatus;
pub use client_hello::ClientHello;
pub use key_exchange::{ClientKeyExchange, ServerKeyExchange, NamedCurve};
pub use server_hello::{ServerHello, ServerHelloDone};
pub use session_ticket::{SessionTicket, TlsSessionTicket};
use std::fmt::Debug;
use crate::{BufferError, CipherSuite, Reader, Version, WriteExt};
pub use certificate::{CertificateVerify, CertificateRequest};
use crate::message::encrypted_extension::EncryptedExtension;

#[derive(Debug)]
pub enum Message<'a> {
    ClientHello(ClientHello<'a>),
    ServerHello(ServerHello<'a>),
    Certificate(Certificates<'a>),
    ServerKeyExchange(ServerKeyExchange<'a>),
    ServerHelloDone(ServerHelloDone),
    ClientKeyExchange(ClientKeyExchange<'a>),
    NewSessionTicket(SessionTicket<'a>),
    Payload(Payload<'a>),
    CertificateStatus(CertificateStatus<'a>),
    CertificateRequest(CertificateRequest<'a>),
    CertificateVerify(CertificateVerify<'a>),
    Alert(Alert),
    CipherSpec,
    Finished(Payload<'a>),
    EncryptedExtension(EncryptedExtension<'a>),
}

impl<'a> Message<'a> {
    pub fn from_bytes(bytes: &'a mut [u8], payload: bool, suite: Option<&CipherSuite>, version: Version) -> RlsResult<Message<'a>> {
        if !payload {
            let handshake_type = HandshakeType::from_byte(bytes[0]).unwrap();
            match handshake_type {
                HandshakeType::ClientHello => Ok(Message::ClientHello(ClientHello::from_bytes(handshake_type, Reader::from_slice(&bytes[1..]))?)),
                HandshakeType::ServerHello => Ok(Message::ServerHello(ServerHello::from_reader(handshake_type, Reader::from_slice(&bytes[1..]))?)),
                HandshakeType::Certificate => Ok(Message::Certificate(Certificates::from_reader(handshake_type, version, Reader::from_slice(&bytes[1..]))?)),
                HandshakeType::ServerKeyExchange => Ok(Message::ServerKeyExchange(ServerKeyExchange::from_reader(handshake_type, Reader::from_slice(&bytes[1..]))?)),
                HandshakeType::ServerHelloDone => Ok(Message::ServerHelloDone(ServerHelloDone::from_reader(handshake_type, Reader::from_slice(&bytes[1..]))?)),
                HandshakeType::ClientKeyExchange => Ok(Message::ClientKeyExchange(ClientKeyExchange::from_reader(handshake_type, Reader::from_slice(&bytes[1..]), suite)?)),
                HandshakeType::NewSessionTicket => Ok(Message::NewSessionTicket(SessionTicket::from_reader(handshake_type, Reader::from_slice(&bytes[1..]), version)?)),
                HandshakeType::CertificateStatus => Ok(Message::CertificateStatus(CertificateStatus::from_reader(handshake_type, Reader::from_slice(&bytes[1..]))?)),
                HandshakeType::CertificateRequest => Ok(Message::CertificateRequest(CertificateRequest::from_reader(handshake_type, Reader::from_slice(&bytes[1..]))?)),
                HandshakeType::CertificateVerify => Ok(Message::CertificateVerify(CertificateVerify::from_reader(handshake_type, Reader::from_slice(&bytes[1..]))?)),
                HandshakeType::Finish => {
                    println!("{:?}", bytes);
                    let len = u32::from_be_bytes([0, bytes[1], bytes[2], bytes[3]]) as usize;
                    Ok(Message::Finished(Payload::from_slice(&mut bytes[4..4 + len])))
                }
                HandshakeType::EncryptedExtensions => Ok(Message::EncryptedExtension(EncryptedExtension::from_reader(handshake_type, Reader::from_slice(&bytes[1..])).unwrap())),
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
            Message::CipherSpec => 1,
            Message::Finished(v) => 3 + v.as_slice().len(),
            Message::EncryptedExtension(v) => v.len()
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
            Message::Finished(v) => {
                writer.write_u16(v.as_slice().len() as u16)?;
                writer.write_slice(v.as_slice())
            }
            Message::EncryptedExtension(v) => v.write_to(writer)
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

#[rustfmt::skip]
#[derive(Debug, Copy, Clone)]
#[repr(u8)]
pub enum HandshakeType {
    ClientHello         = 1,
    ServerHello         = 2,
    NewSessionTicket    = 4,
    EncryptedExtensions = 8,
    Certificate         = 11,
    ServerKeyExchange   = 12,
    CertificateRequest  = 13,
    ServerHelloDone     = 14,
    CertificateVerify   = 15,
    ClientKeyExchange   = 16,
    Finish              = 20,
    CertificateStatus   = 22,
}

impl HandshakeType {
    pub fn from_byte(byte: u8) -> Option<HandshakeType> {
        match byte {
            1 => Some(HandshakeType::ClientHello),
            2 => Some(HandshakeType::ServerHello),
            4 => Some(HandshakeType::NewSessionTicket),
            8 => Some(HandshakeType::EncryptedExtensions),
            11 => Some(HandshakeType::Certificate),
            12 => Some(HandshakeType::ServerKeyExchange),
            13 => Some(HandshakeType::CertificateRequest),
            14 => Some(HandshakeType::ServerHelloDone),
            15 => Some(HandshakeType::CertificateVerify),
            16 => Some(HandshakeType::ClientKeyExchange),
            20 => Some(HandshakeType::Finish),
            22 => Some(HandshakeType::CertificateStatus),
            _ => None
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}
