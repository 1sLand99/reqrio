use crate::connection::QUICError;
use crate::{Buf, ReadExt, Reader};

#[repr(u64)]
#[derive(Debug)]
pub enum FrameType<'a> {
    Padding(usize) = 0x00,
    Ping = 0x01,
    Ack {
        largest_acknowledged: u64,
        ack_delay: u64,
        ack_range_count: u64,
        first_ack_range: u64,
    }= 0x02,
    AckEcn = 0x03,
    ResetStream = 0x04,
    StopSending = 0x05,
    Crypto {
        offset: usize,
        value: Buf<'a>,
    } = 0x06,
    NewToken = 0x07,
    Stream(u64),
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

impl<'a> FrameType<'a> {
    pub(crate) fn from_reader(reader: &mut Reader<'a>) -> Result<FrameType<'a>, QUICError> {
        let typ = super::read_variant(reader)? as u64;
        match typ {
            0x00 => {
                let len = reader.find(|&x| x != 0).unwrap_or(reader.unread_len());
                let value = Buf::Ref(reader.read_slice(len)?);
                Ok(FrameType::Padding(value.len()))
            }
            0x01 => Ok(FrameType::Ping),
            0x02 => Ok(FrameType::Ack {
                largest_acknowledged: super::read_variant(reader)? as u64,
                ack_delay: super::read_variant(reader)? as u64,
                ack_range_count: super::read_variant(reader)? as u64,
                first_ack_range: super::read_variant(reader)? as u64,

            }),
            0x06 => {
                let offset = super::read_variant(reader)?;
                let len = super::read_variant(reader)?;
                Ok(FrameType::Crypto {
                    offset,
                    value: Buf::Ref(reader.read_slice(len)?),
                })
            }
            _ => unreachable!()
        }
    }
}