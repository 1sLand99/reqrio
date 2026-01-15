use crate::error::RlsResult;
use crate::extend::Aead;
use crate::RlsError;
use super::message::{Message, Payload};
use super::version::Version;

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
    pub fn new() -> RecordLayer<'a> {
        RecordLayer {
            context_type: RecordType::CipherSpec,
            version: Version::new(0),
            len: 0,
            messages: vec![],
        }
    }
    pub fn from_bytes(bytes: &mut [u8], payload: bool) -> RlsResult<RecordLayer<'_>> {
        if bytes.len() < 5 { return Err(RlsError::MessageTooShort); }
        let (head, messages) = bytes.split_at_mut(5);
        let mut res = RecordLayer::new();
        res.context_type = RecordType::from_byte(head[0]).ok_or("LayerType Unknown")?;
        res.version = Version::new(u16::from_be_bytes([head[1], head[2]]));
        res.len = u16::from_be_bytes([head[3], head[4]]);
        if messages.len() < res.len as usize { return Err("record body not enough".into()); }
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
                        res.messages.push(Message::from_bytes(message, payload)?)
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
                    res.messages.push(Message::CipherSpec);
                    break;
                }
                RecordType::CipherSpec => {
                    index = index + 1;
                    res.messages.push(Message::CipherSpec)
                }
            };
        }

        Ok(res)
    }

    pub fn handshake_bytes(&self) -> Vec<u8> {
        let mut res = self.head_bytes();
        let msg = self.messages.iter().map(|x| x.as_bytes()).collect::<Vec<_>>().concat();
        res.extend((msg.len() as u16).to_be_bytes());
        res.extend(msg);
        res
    }

    pub fn head_bytes(&self) -> Vec<u8> {
        let mut res = vec![self.context_type.as_u8()];
        res.extend(self.version.as_bytes());
        res
    }
}


pub struct RecordBuffer<'a> {
    pub(crate) aead: &'a Aead,
    head: &'a mut [u8],
    pub(crate) payload: Payload<'a>,
}


impl<'a> RecordBuffer<'a> {
    pub fn set_payload_len(&mut self, len: usize) {
        let len = len as u16;
        self.head[3..5].copy_from_slice(&len.to_be_bytes());
    }

    pub fn set_head(&mut self, rt: RecordType, v: Version) {
        self.head[0] = rt as u8;
        self.head[1..3].copy_from_slice(&v.as_u16().to_be_bytes());
    }

    pub fn set_payload(&mut self, payload: &[u8]) {
        let payload_range = self.aead.payload_range(payload.len());
        self.payload.value[payload_range].copy_from_slice(payload);
        self.payload.len = payload.len();
    }

    pub fn add_explicit_iv(&mut self, iv: &[u8]) {
        let explicit = match self.aead {
            Aead::AES_128_GCM | Aead::AES_256_GCM => &iv[4..],
            Aead::ChaCha20_POLY1305 => &[],
            Aead::AES_128_CBC_SHA | Aead::AES_256_CBC_SHA => iv,
            _ => panic!("unsupported cipher specification"),
        };
        let iv_range = self.aead.explicit_range();
        if iv_range.start == iv_range.end { return; }
        self.payload.value[iv_range].copy_from_slice(explicit);
    }

    pub fn from_buffer(aead: &'a Aead, buffer: &'a mut [u8]) -> RecordBuffer<'a> {
        let (head, payload) = buffer.split_at_mut(5);
        RecordBuffer {
            aead,
            head,
            payload: Payload::from_slice(payload),
        }
    }

    pub fn aad(&self, seq: u64) -> [u8; 13] {
        let mut res = [0; 13];
        res[0..8].copy_from_slice(&seq.to_be_bytes());
        res[8..11].copy_from_slice(&self.head[..3]);
        res[11..13].copy_from_slice(&(self.payload.len as u16).to_be_bytes());
        res
    }
}