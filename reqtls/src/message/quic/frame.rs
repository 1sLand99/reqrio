use crate::connection::QUICError;
use crate::{Buf, BufferError, ReadExt, Reader, WriteExt};

#[repr(u16)]
#[allow(non_camel_case_types)]
#[derive(Debug)]
pub enum TransportError {
    NO_ERROR = 0x00,
    INTERNAL_ERROR = 0x01,
    CONNECTION_REFUSED = 0x02,
    FLOW_CONTROL_ERROR = 0x03,
    STREAM_LIMIT_ERROR = 0x04,
    STREAM_STATE_ERROR = 0x05,
    FINAL_SIZE_ERROR = 0x06,
    FRAME_ENCODING_ERROR = 0x07,
    TRANSPORT_PARAMETER_ERROR = 0x08,
    CONNECTION_ID_LIMIT_ERROR = 0x09,
    PROTOCOL_VIOLATION = 0x0a,
    INVALID_TOKEN = 0x0b,
    APPLICATION_ERROR = 0x0c,
    CRYPTO_BUFFER_EXCEEDED = 0x0d,
    KEY_UPDATE_ERROR = 0x0e,
    AEAD_LIMIT_REACHED = 0x0f,
    NO_VIABLE_PATH = 0x10,
    //0x0100 - 0x01ff
    CRYPTO_ERROR(u16),
}

impl From<u16> for TransportError {
    fn from(value: u16) -> Self {
        match value {
            0x00 => TransportError::NO_ERROR,
            0x01 => TransportError::INTERNAL_ERROR,
            0x02 => TransportError::CONNECTION_REFUSED,
            0x03 => TransportError::FLOW_CONTROL_ERROR,
            0x04 => TransportError::STREAM_LIMIT_ERROR,
            0x05 => TransportError::STREAM_STATE_ERROR,
            0x06 => TransportError::FINAL_SIZE_ERROR,
            0x07 => TransportError::FRAME_ENCODING_ERROR,
            0x08 => TransportError::TRANSPORT_PARAMETER_ERROR,
            0x09 => TransportError::CONNECTION_ID_LIMIT_ERROR,
            0x0a => TransportError::PROTOCOL_VIOLATION,
            0x0b => TransportError::INVALID_TOKEN,
            0x0c => TransportError::APPLICATION_ERROR,
            0x0d => TransportError::CRYPTO_BUFFER_EXCEEDED,
            0x0e => TransportError::KEY_UPDATE_ERROR,
            0x0f => TransportError::AEAD_LIMIT_REACHED,
            0x10 => TransportError::NO_VIABLE_PATH,
            _ => TransportError::CRYPTO_ERROR(value),
        }
    }
}


#[repr(u64)]
#[derive(Debug)]
pub enum QUICFrame<'a> {
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
    ConnectionCloseTrp {
        err_code: TransportError,
        frame_typ: usize,
        reason: &'a str,
    }= 0x1c,
    ConnectionCloseApp = 0x1d,
    HandshakeDone = 0x1e,
}

impl<'a> QUICFrame<'a> {
    pub(crate) fn from_reader(reader: &mut Reader<'a>) -> Result<QUICFrame<'a>, QUICError> {
        let typ = crate::quic::read_variant(reader)? as u64;
        match typ {
            0x00 => {
                let len = reader.find(|&x| x != 0).unwrap_or(reader.unread_len());
                let value = Buf::Ref(reader.read_slice(len)?);
                Ok(QUICFrame::Padding(value.len()))
            }
            0x01 => Ok(QUICFrame::Ping),
            0x02 => Ok(QUICFrame::Ack {
                largest_acknowledged: crate::quic::read_variant(reader)? as u64,
                ack_delay: crate::quic::read_variant(reader)? as u64,
                ack_range_count: crate::quic::read_variant(reader)? as u64,
                first_ack_range: crate::quic::read_variant(reader)? as u64,

            }),
            0x06 => {
                let offset = crate::quic::read_variant(reader)?;
                let len = crate::quic::read_variant(reader)?;
                Ok(QUICFrame::Crypto {
                    offset,
                    value: Buf::Ref(reader.read_slice(len)?),
                })
            }
            0x1c => {
                let err_code = crate::quic::read_variant(reader)? as u16;
                let frame_typ = crate::quic::read_variant(reader)?;
                let reason_len = crate::quic::read_variant(reader)?;
                Ok(QUICFrame::ConnectionCloseTrp {
                    err_code: err_code.into(),
                    frame_typ,
                    reason: reader.read_str::<QUICError>(reason_len)?,
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
            QUICFrame::Padding(size) => *size,
            QUICFrame::Ping => 1,
            QUICFrame::Crypto { offset, value } => {
                let offset_size = crate::quic::variant_len(*offset);
                let value_size = crate::quic::variant_len(value.len());
                1 + offset_size + value_size + value.len()
            }
            QUICFrame::Ack { largest_acknowledged, ack_delay, ack_range_count, first_ack_range } => {
                crate::quic::variant_len(*largest_acknowledged as usize) +
                    crate::quic::variant_len(*ack_delay as usize) +
                    crate::quic::variant_len(*ack_range_count as usize) +
                    crate::quic::variant_len(*first_ack_range as usize)
            }
            _ => todo!()
        }
    }

    pub fn write_to<W: WriteExt>(&self, writer: &mut W) -> Result<(), BufferError> {
        match self {
            QUICFrame::Padding(size) => writer.write_slice(&vec![0; *size]),
            QUICFrame::Ping => writer.write_u8(0x01),
            QUICFrame::Crypto { offset, value } => {
                writer.write_u8(0x06)?;
                crate::quic::write_variant(*offset, writer)?;
                crate::quic::write_variant(value.len(), writer)?;
                writer.write_slice(value.as_ref())
            }
            QUICFrame::Ack { largest_acknowledged, ack_delay, ack_range_count, first_ack_range } => {
                crate::quic::write_variant(*largest_acknowledged as usize, writer)?;
                crate::quic::write_variant(*ack_delay as usize, writer)?;
                crate::quic::write_variant(*ack_range_count as usize, writer)?;
                crate::quic::write_variant(*first_ack_range as usize, writer)
            }
            _ => todo!()
        }
    }
}