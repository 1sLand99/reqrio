use super::message::{Message, Payload};
use super::version::Version;
use crate::error::RlsResult;
use crate::{Alert, BufferError, CipherSuite, WriteExt, ALPN};

#[derive(Debug, Copy, Clone)]
pub enum RecordType {
    CipherSpec = 0x14,
    Alert = 0x15,
    HandShake = 0x16,
    ApplicationData = 0x17,

}

impl RecordType {
    pub fn from_byte(byte: u8) -> Option<RecordType> {
        match byte {
            0x14 => Some(RecordType::CipherSpec),
            0x15 => Some(RecordType::Alert),
            0x16 => Some(RecordType::HandShake),
            0x17 => Some(RecordType::ApplicationData),
            _ => None
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}


#[derive(Debug)]
pub struct RecordLayer<'a> {
    pub context_type: RecordType,
    pub version: Version,
    pub len: u16,
    pub messages: Vec<Message<'a>>,
}

impl<'a> RecordLayer<'a> {
    pub fn new(rt: RecordType) -> RecordLayer<'a> {
        RecordLayer {
            context_type: rt,
            version: Version::TLS_1_2,
            len: 0,
            messages: vec![],
        }
    }

    pub fn handshake() -> RecordLayer<'a> {
        RecordLayer::new(RecordType::HandShake)
    }

    pub fn from_bytes(bytes: &'a mut [u8], payload: bool, suite: Option<&CipherSuite>) -> RlsResult<RecordLayer<'a>> {
        if bytes.len() < 5 { return Err(BufferError::Insufficient.into()); }
        let (head, messages) = bytes.split_at_mut(5);
        let mut res = RecordLayer::new(RecordType::from_byte(head[0]).ok_or("LayerType Unknown")?);
        res.version = Version::new(u16::from_be_bytes([head[1], head[2]]));
        res.len = u16::from_be_bytes([head[3], head[4]]);
        if messages.len() < res.len as usize { return Err(BufferError::Insufficient.into()); }
        let (mut messages, _) = messages.split_at_mut(res.len as usize);
        let mut index = 0;
        let total_len = messages.len();

        while index < total_len {
            match res.context_type {
                RecordType::HandShake => {
                    if !payload {
                        let msg_len = u32::from_be_bytes([0, messages[1], messages[2], messages[3]]) as usize;
                        let (message, reset) = messages.split_at_mut(msg_len + 4);
                        messages = reset;
                        index = index + 4 + msg_len;
                        res.messages.push(Message::from_bytes(message, payload, suite)?)
                    } else {
                        res.messages.push(Message::Payload(Payload::from_slice(messages)));
                        break;
                    }
                }
                RecordType::ApplicationData => {
                    res.messages.push(Message::Payload(Payload::from_slice(messages)));
                    break;
                }
                RecordType::Alert => if payload {
                    res.messages.push(Message::Payload(Payload::from_slice(messages)));
                    break;
                } else {
                    res.messages.push(Message::Alert(Alert::from_bytes(messages)?));
                    break;
                }
                RecordType::CipherSpec => {
                    index += 1;
                    res.messages.push(Message::CipherSpec)
                }
            };
        }

        Ok(res)
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W, key_size: u8) -> RlsResult<usize> {
        let offset = writer.offset().end;
        let sni = self.messages[0].client().map(|x| x.server_name().unwrap_or("")).unwrap_or("").to_string();
        let h2 = self.messages[0].client().map(|x| x.alps().map(|x| x.values().iter().any(|x| x == &ALPN::Http20)).unwrap_or(false)).unwrap_or(false);
        writer.write_u8(self.context_type as u8)?;
        writer.write_u16(self.version.into_inner())?;
        let len = self.messages.iter().map(|x| x.len(key_size)).sum::<usize>();
        writer.write_u16(len as u16)?;
        for message in self.messages {
            message.write_to(writer, key_size)?;
        }
        writer.flush(offset, sni, h2)
    }
}

