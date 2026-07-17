use crate::connection::QUICError;
use crate::{Buf, ReadExt, Reader};

#[repr(u8)]
#[derive(Debug)]
pub enum FrameType {
    Padding = 0x00,
    Ping = 0x01,
    Ack = 0x02,
    AckEcn = 0x03,
    ResetStream = 0x04,
    StopSending = 0x05,
    Crypto = 0x06,
    NewToken = 0x07,
    Stream(u8),
    MaxData = 0x10,
    MaxStreamData = 0x11,
    MaxStreamsBidi = 0x12,
    MaxStreamsUni = 0x13,
    DataBlocked = 0x14,
    StreamDataBlocked = 0x15,
    StreamsBlockedBidi = 0x16,
    StreamsBlockedUnu = 0x17,
    NewConnectionId = 0x18,
    RetireConnectionId = 0x19,
    PathChallenge = 0x1a,
    PathResponse = 0x1b,
    ConnectionCloseTrp = 0x1c,
    ConnectionCloseApp = 0x1d,
    HandshakeDone = 0x1e,
}

impl From<u8> for FrameType {
    fn from(val: u8) -> Self {
        match val {
            0x00 => FrameType::Padding,
            0x01 => FrameType::Ping,
            0x02 => FrameType::Ack,
            0x03 => FrameType::AckEcn,
            0x04 => FrameType::ResetStream,
            0x05 => FrameType::StopSending,
            0x06 => FrameType::Crypto,
            0x07 => FrameType::NewToken,
            0x08..0x10 => FrameType::Stream(val),
            0x10 => FrameType::MaxData,
            0x11 => FrameType::MaxStreamData,
            0x12 => FrameType::MaxStreamsBidi,
            0x13 => FrameType::MaxStreamsUni,
            0x14 => FrameType::DataBlocked,
            0x15 => FrameType::StreamDataBlocked,
            0x16 => FrameType::StreamsBlockedBidi,
            0x17 => FrameType::StreamsBlockedUnu,
            0x18 => FrameType::NewConnectionId,
            0x19 => FrameType::RetireConnectionId,
            0x1a => FrameType::PathChallenge,
            0x1b => FrameType::PathResponse,
            0x1c => FrameType::ConnectionCloseTrp,
            0x1d => FrameType::ConnectionCloseApp,
            0x1e => FrameType::HandshakeDone,
            _ => unimplemented!(),
        }
    }
}


#[derive(Debug)]
pub struct Frame<'a> {
    typ: FrameType,
    offset: usize,
    len: usize,
    payload: Buf<'a>,
}
impl<'a> Default for Frame<'a> {
    fn default() -> Self {
        Frame {
            typ: FrameType::Padding,
            offset: 0,
            len: 0,
            payload: Buf::Ref(&[]),
        }
    }
}

impl<'a> Frame<'a> {
    pub(crate) fn from_reader(reader: &mut Reader<'a>) -> Result<Frame<'a>, QUICError> {
        let typ = FrameType::from(reader.read_u8()?);
        match typ {
            FrameType::Padding => {
                let len = reader.find(|&x| x != 0).unwrap_or(reader.unread_len());
                Ok(Frame {
                    typ,
                    len,
                    payload: Buf::Ref(reader.read_slice(len)?),
                    ..Default::default()
                })
            }
            FrameType::Ping => Ok(Frame {
                typ,
                ..Default::default()
            }),
            _ => {
                let offset = super::read_varint(reader)?;
                let len = super::read_varint(reader)?;
                Ok(Frame {
                    typ,
                    offset,
                    len,
                    payload: Buf::Ref(reader.read_slice(len)?),
                })
            }
        }
    }
}