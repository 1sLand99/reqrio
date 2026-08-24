mod ack;
mod sync;
#[cfg(feature = "aync")]
mod aync;

use reqtls::quic::*;
use reqtls::*;
use std::collections::HashMap;
use std::ops::Range;
pub use sync::QUICStreamS;
#[cfg(feature = "aync")]
pub use aync::QUICStreamA;

#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone)]
pub(crate) enum QId {
    HId,
    AId(u64),
}

#[derive(Debug)]
pub(crate) struct Queue {
    pub(crate) bid: u64,
    pub(crate) fin: bool,
    pub(crate) offset: usize,
    pub(crate) pos: Range<usize>,
}

pub(crate) struct QUICParams<'a> {
    dcid: &'a mut Buf<'static>,
    token: &'a mut Buf<'static>,
    conn: &'a mut QUICConnection,
    ur_buffer: &'a mut Buffer,
    sent_num: &'a mut HashMap<u64, Range<usize>>,
    packet_offsets: &'a mut Vec<(PacketType, Range<usize>)>,
    buffer_size: &'a mut u64,
    task_buffer: &'a mut HashMap<u64, (Buffer, usize)>,
    buffer_queues: &'a mut HashMap<QId, Vec<Queue>>,
    idle_buffer: &'a mut Vec<(u64, Buffer)>,
}

pub trait QUICHandler{
    fn free_buffer(task_buffer: &mut HashMap<u64, (Buffer, usize)>, idle_buffer: &mut Vec<(u64, Buffer)>, bid: u64) -> Result<(), QUICError> {
        if task_buffer[&bid].1 <= 1 {
            if let Some((mut buffer, _)) = task_buffer.remove(&bid) {
                buffer.reset();
                idle_buffer.push((bid, buffer))
            }
        } else if let Some((_, buf_ref)) = task_buffer.get_mut(&bid) {
            *buf_ref -= 1;
        }
        Ok(())
    }

    fn handle_packet(params: QUICParams, mut off: Range<usize>) -> Result<QUICParams, QUICError> {
        let mut reader = Reader::from_slice(params.ur_buffer.slice(off.clone()));
        let mut packet = QUICPacket::from_reader(&mut reader)?;
        if packet.flag().packet_type() == PacketType::Initial {
            params.conn.make_initial_cipher(packet.dc_id(), false)?;
        } else if packet.flag().packet_type() == PacketType::Retry {
            *params.token = Buf::Vec(packet.token().to_vec());
            *params.dcid = Buf::Vec(packet.sc_id().to_vec());
            return Err(QUICError::InitialRetry);
        }
        if params.dcid.as_ref() != packet.sc_id().as_ref() && !packet.sc_id().as_ref().is_empty() {
            *params.dcid = Buf::Vec(packet.sc_id().as_ref().to_vec());
        }
        let (bid, mut idle_buffer) = if params.idle_buffer.is_empty() {
            let bid = *params.buffer_size;
            *params.buffer_size = bid + 1;
            (bid, Buffer::with_capacity(1500))
        } else { params.idle_buffer.remove(0) };
        let len = params.conn.read_message(&mut packet, &mut reader, idle_buffer.unfilled()).unwrap();
        idle_buffer.add_len(len);
        assert_eq!(packet.len(), reader.position());
        let zero_len = reader.find(|&b| b != 0).unwrap_or(reader.unread_len());
        println!("1111111111={}-{:?}", zero_len, &reader.inner()[reader.position()..]);
        reader.read_slice(zero_len)?;
        off.start += reader.position();
        if !off.is_empty() {
            let flag = QUICFlag::from_raw(reader.inner()[reader.position()]);
            params.packet_offsets.insert(0, (flag.packet_type(), off));
        }
        Self::handle_frames(params, bid, idle_buffer)
    }

    fn handle_frames(params: QUICParams, bid: u64, buffer: Buffer) -> Result<QUICParams, QUICError> {
        let mut reader = Reader::from_slice(buffer.filled());
        let mut buf_ref = 0;
        while reader.unread_len() > 0 {
            let frame = QUICFrame::from_reader(&mut reader).unwrap();
            match frame {
                QUICFrame::Ack { largest_acknowledged, first_ack_range, .. } => {
                    let start = largest_acknowledged - first_ack_range;
                    for large in start..=largest_acknowledged {
                        params.sent_num.remove(&large);
                    }
                }
                QUICFrame::ConnectionCloseTrp { reason, err_code, .. } => return Err(QUICError::TransportError { reason: reason.to_string(), err_code }),
                QUICFrame::Crypto { offset, value, buf_pos } => {
                    #[cfg(feature = "log")]
                    trace!("[QUIC Frame] off={}; pd={}; pos={:?};", offset, value.len(), buf_pos);
                    let queues = params.buffer_queues.entry(QId::HId).or_insert_with(|| Vec::with_capacity(30));
                    queues.push(Queue {
                        bid,
                        fin: false,
                        offset,
                        pos: buf_pos,
                    });
                    buf_ref += 1;
                }
                QUICFrame::Stream { flag, sid, offset, payload, buf_pos } => {
                    #[cfg(feature = "log")]
                    trace!("[QUIC Frame] fin={}; sid={}; off={}; pd={}; pos={:?}", flag.fin(), sid, offset, payload.len(), buf_pos);
                    let queues = params.buffer_queues.entry(QId::AId(sid)).or_insert_with(|| Vec::with_capacity(30));
                    queues.push(Queue {
                        bid,
                        fin: flag.fin(),
                        offset,
                        pos: buf_pos,
                    });
                    buf_ref += 1;
                }
                QUICFrame::Ping |
                QUICFrame::Padding(_) |
                QUICFrame::HandshakeDone |
                QUICFrame::NewConnectionId { .. } |
                QUICFrame::MaxStreamsBidi(_) |
                QUICFrame::MaxStreamData { .. } |
                QUICFrame::NewToken(_) => {}
                _ => unreachable!()
            }
        }
        if buf_ref != 0 { params.task_buffer.insert(bid, (buffer, buf_ref)); }
        Ok(params)
    }
}