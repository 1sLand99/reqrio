use crate::connection::QUICError;
use crate::{Buf, BufferError, ReadExt, Reader, WriteExt};

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
        let typ = crate::quic::read_variant(reader)? as u64;
        match typ {
            0x00 => {
                let len = reader.find(|&x| x != 0).unwrap_or(reader.unread_len());
                let value = Buf::Ref(reader.read_slice(len)?);
                Ok(FrameType::Padding(value.len()))
            }
            0x01 => Ok(FrameType::Ping),
            0x02 => Ok(FrameType::Ack {
                largest_acknowledged: crate::quic::read_variant(reader)? as u64,
                ack_delay: crate::quic::read_variant(reader)? as u64,
                ack_range_count: crate::quic::read_variant(reader)? as u64,
                first_ack_range: crate::quic::read_variant(reader)? as u64,

            }),
            0x06 => {
                let offset = crate::quic::read_variant(reader)?;
                let len = crate::quic::read_variant(reader)?;
                Ok(FrameType::Crypto {
                    offset,
                    value: Buf::Ref(reader.read_slice(len)?),
                })
            }
            _ => unreachable!()
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    
    pub fn len(&self) -> usize {
        match self {
            FrameType::Padding(size) => *size,
            FrameType::Ping => 1,
            FrameType::Crypto { offset, value } => {
                let offset_size = crate::quic::variant_len(*offset);
                let value_size = crate::quic::variant_len(value.len());
                1 + offset_size + value_size + value.len()
            }
            _ => todo!()
        }
    }

    pub fn write_to<W: WriteExt>(&self, writer: &mut W) -> Result<(), BufferError> {
        match self {
            FrameType::Padding(size) => writer.write_slice(&vec![0; *size]),
            FrameType::Ping => writer.write_u8(0x01),
            FrameType::Crypto { offset, value } => {
                writer.write_u8(0x06)?;
                crate::quic::write_variant(*offset, writer)?;
                crate::quic::write_variant(value.len(), writer)?;
                writer.write_slice(value.as_ref())
            }
            _ => todo!()
        }
    }
}