mod ack;

use crate::error::HlsResult;
use crate::stream::quic::ack::QUICAck;
use reqtls::quic::*;
use reqtls::*;
use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::ops::Range;
use std::time::Duration;
use std::mem;
use crate::HlsError;

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


pub struct QUICStreamS {
    socket: UdpSocket,
    ur_buffer: Buffer,
    tr_last_offset: usize,
    tr_buffer: Buffer,
    uw_buffer: Buffer,

    tw_buffer: Buffer,
    conn: QUICConnection,
    sent_num: HashMap<u64, Range<usize>>,

    addr: SocketAddr,
    seq: u64,
    dcid: Buf<'static>,
    token: Buf<'static>,

    handshake_finish: bool,
    encrypted_channel: bool,
    hello_retrying: bool,
    crypto_offset: usize,

    packet_offsets: Vec<(PacketType, Range<usize>)>,
    current: PacketType,
    idle_buffer: Vec<(u64, Buffer)>,

    buffer_size: u64,
    task_buffer: HashMap<u64, (Buffer, usize)>,
    buffer_queues: HashMap<QId, Vec<Queue>>,

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


impl QUICStreamS {
    pub fn connect(socket: UdpSocket, remote_addr: SocketAddr, config: ClientConfig<'_>) -> HlsResult<QUICStreamS> {
        socket.set_read_timeout(Some(Duration::from_millis(3000)))?;
        let session = config.session.clone().unwrap_or_default();
        let key_log = config.key_log.clone();
        QUICStreamS {
            socket,
            ur_buffer: Buffer::with_capacity(6000),
            tr_last_offset: 0,
            tr_buffer: Buffer::with_capacity(8192),
            uw_buffer: Buffer::with_capacity(15000),
            tw_buffer: Buffer::with_capacity(16438),
            conn: QUICConnection::new(session, key_log, config.verify),
            sent_num: HashMap::new(),
            addr: remote_addr,
            seq: 1,
            dcid: Buf::Vec(rand::random::<[u8; 8]>().to_vec()),
            token: Buf::Ref(&[]),
            handshake_finish: false,
            encrypted_channel: false,
            hello_retrying: false,
            crypto_offset: 0,
            packet_offsets: vec![],
            current: PacketType::Initial,
            idle_buffer: vec![],
            buffer_size: 0,
            task_buffer: Default::default(),
            buffer_queues: Default::default(),
        }.handshake(config)
    }

    fn send_client_hello(&mut self, config: &mut ClientConfig, force: bool) -> Result<(), QUICError> {
        self.tw_buffer.reset();
        self.conn.make_initial_cipher(&self.dcid, force)?;
        self.handle_client_hello(config)?;
        self.tw_buffer.used_empty(5);
        self.write_buffer(PacketType::Initial, None)
    }

    fn handle_message(&mut self, config: &mut Config) -> Result<(), QUICError> {
        let mut reader = Reader::from_slice(self.tr_buffer.filled());
        let mut read_len = 0;
        while let Ok(message) = Message::from_reader(&mut reader, &RecordType::HandShake, KeyExchangeAlg::NULL, &Version::TLS_1_3) {
            read_len += message.encoded.len();
            let is_server_hello = message.parsed.server().is_some();
            QUICStreamS::handle_handshake(&mut StreamParam {
                handshake_finish: &mut self.handshake_finish,
                encrypted_channel: &mut self.encrypted_channel,
                hello_retrying: &mut self.hello_retrying,
                write_buffer: &mut self.tw_buffer,
                conn: self.conn.tls_conn(),
            }, Some(config), message).unwrap();
            if is_server_hello && !self.hello_retrying {
                self.conn.make_sample_cipher(KeyType::Handshake)?;
                self.current = PacketType::Handshake;
                self.tr_buffer.reset();
                self.tr_last_offset = 0;
                return Ok(());
            }
        }
        self.tr_buffer.used_empty(read_len);
        Ok(())
    }

    fn handshake(mut self, mut config: ClientConfig) -> HlsResult<QUICStreamS> {
        self.send_client_hello(&mut config, false)?;
        let mut config = Config::Client(config);
        while !self.handshake_finish {
            match self.read_next_packet() {
                Err(QUICError::InitialRetry) => {
                    self.crypto_offset = 0;
                    self.tr_last_offset = 0;
                    self.ur_buffer.reset();
                    self.packet_offsets.clear();
                    self.current = PacketType::Initial;
                    let config = config.client_mut().ok_or("missing client config")?;
                    self.send_client_hello(config, true)?;
                    continue;
                }
                Err(e) => return Err(HlsError::QUIC(e)),
                Ok(_) => {}
            };
            self.handle_queues(|_, _, _| Ok(None))?;
            self.send_ack(QUICFlag::new_long(PacketType::Handshake))?;
            self.handle_message(&mut config)?;
            if !self.tw_buffer.is_empty() {
                self.send_ack(QUICFlag::new_long(PacketType::Handshake))?;
                if self.hello_retrying { self.tw_buffer.used_empty(5); } else { self.crypto_offset = 0; }
                self.write_buffer(if self.hello_retrying { PacketType::Initial } else { PacketType::Handshake }, None)?;
            }
        }
        self.conn.recv_nums_mut().clear();
        self.conn.tls_conn().make_cipher(false)?;
        self.conn.make_sample_cipher(KeyType::Application)?;
        self.current = PacketType::ShortHeader;
        self.tr_buffer.reset();
        self.tr_last_offset = 0;
        Ok(self)
    }

    fn build_packet<'a>(seq: u64, dcid: &'a Buf<'a>, token: &'a Buf<'a>, typ: PacketType, pd_len: usize) -> QUICPacket<'a> {
        match typ {
            PacketType::Initial | PacketType::Handshake => QUICPacket::new_long(typ, seq, pd_len, dcid.as_ref(), token),
            PacketType::ShortHeader => QUICPacket::new_short(typ, seq, pd_len, dcid.as_ref()),
            PacketType::Retry => unreachable!(),
        }
    }

    pub fn send_ack(&mut self, flag: QUICFlag) -> Result<(), QUICError> {
        if self.conn.recv_nums().is_empty() { return Ok(()); }
        let mut ack = QUICAck {
            flag,
            conn: &mut self.conn,
            uw_buffer: &mut self.uw_buffer,
            dcid: &self.dcid,
            seq: &mut self.seq,
        };
        self.socket.send_to(ack.build()?, self.addr)?;
        self.conn.recv_nums_mut().reset_sent_largest();
        Ok(())
    }

    fn write_buffer(&mut self, typ: PacketType, buf: Option<&[u8]>) -> Result<(), QUICError> {
        let mut frames = vec![QUICFrame::Ping];
        let mut pd_len = 1;
        let buf = if let Some(buf) = buf { buf } else { self.tw_buffer.filled() };
        for chunk in buf.chunks(350) {
            let frame = QUICFrame::Crypto {
                offset: self.crypto_offset,
                value: Buf::Ref(chunk),
                buf_pos: 0..0,
            };
            pd_len += frame.len();
            self.crypto_offset += chunk.len();
            frames.push(frame);
            if pd_len + 350 >= 1210 {
                let packet = Self::build_packet(self.seq, &self.dcid, &self.token, typ, mem::take(&mut pd_len));
                let (offset, filled) = self.conn.build_message(packet, mem::take(&mut frames), &mut self.uw_buffer)?;
                self.socket.send_to(filled, self.addr).unwrap();
                self.sent_num.insert(self.seq, offset);
                self.seq += 1;
            }
        }
        if !frames.is_empty() {
            let packet = Self::build_packet(self.seq, &self.dcid, &self.token, typ, mem::take(&mut pd_len));
            let (offset, filled) = self.conn.build_message(packet, mem::take(&mut frames), &mut self.uw_buffer)?;
            self.socket.send_to(filled, self.addr)?;
            self.sent_num.insert(self.seq, offset);
            self.seq += 1;
        }
        self.tw_buffer.reset();
        Ok(())
    }

    pub fn read_next_packet(&mut self) -> Result<(), QUICError> {
        println!("{:?} {:?}", self.packet_offsets, self.current);
        if self.packet_offsets.is_empty() { self.ur_buffer.reset(); }
        let pos = self.packet_offsets.iter().position(|&(typ, _)| typ <= self.current);
        let off = match pos {
            Some(pos) => self.packet_offsets.remove(pos).1,
            None => loop {
                let start = self.ur_buffer.end();
                let unfilled = self.ur_buffer.unfilled();
                let len = self.socket.recv(unfilled)?;
                let off = start..start + len;
                let flag = QUICFlag::from_raw(unfilled[0]);
                self.ur_buffer.add_len(len);
                #[cfg(feature = "log")]
                trace!("read flag={:?}; cur={:?}; {}", flag.packet_type(), self.current, flag.packet_type() > self.current);
                if flag.packet_type() > self.current {
                    self.packet_offsets.push((flag.packet_type(), off));
                    continue;
                }
                break off;
            }
        };
        QUICStreamS::handle_packet(QUICParams {
            dcid: &mut self.dcid,
            token: &mut self.token,
            conn: &mut self.conn,
            ur_buffer: &mut self.ur_buffer,
            sent_num: &mut self.sent_num,
            packet_offsets: &mut self.packet_offsets,
            buffer_size: &mut self.buffer_size,
            task_buffer: &mut self.task_buffer,
            buffer_queues: &mut self.buffer_queues,
            idle_buffer: &mut self.idle_buffer,
        }, off)?;

        Ok(())
    }

    pub(crate) fn handle_queues<F>(&mut self, mut worker: F) -> HlsResult<()>
    where
        F: FnMut(&u64, &mut Vec<Queue>, &HashMap<u64, (Buffer, usize)>) -> HlsResult<Option<u64>>,
    {
        let mut keys = Vec::with_capacity(self.buffer_queues.keys().len());
        for (qid, queues) in &mut self.buffer_queues {
            while !queues.is_empty() {
                let bid = match qid {
                    QId::AId(sid) => worker(sid, queues, &self.task_buffer)?,
                    QId::HId => {
                        let pos = queues.iter().position(|x| x.offset == self.tr_last_offset);
                        let Some(pos) = pos else { break };
                        let queue = queues.remove(pos);
                        let (buffer, _) = &self.task_buffer[&queue.bid];
                        self.tr_buffer.check_move(queue.pos.len())?;
                        if self.tr_buffer.unfilled_len() < queue.pos.len() {
                            #[cfg(all(debug_assertions, feature = "log"))]
                            warn!("[QUIC] resize buffer = {}", self.tr_buffer.capacity()*2);
                            self.tr_buffer.resize(queue.pos.len() - self.tr_buffer.unfilled_len())?;
                        }
                        self.tr_last_offset += queue.pos.len();
                        self.tr_buffer.write_slice(buffer.slice(queue.pos))?;
                        Some(queue.bid)
                    }
                };
                let Some(bid) = bid else { break };
                QUICStreamS::free_buffer(&mut self.task_buffer, &mut self.idle_buffer, bid)?;
            }
            if queues.is_empty() { keys.push(*qid) }
        }
        for key in keys {
            self.buffer_queues.remove(&key);
        }
        Ok(())
    }

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
        QUICStreamS::handle_frames(params, bid, idle_buffer)
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

    pub fn write_stream(&mut self, streams: Vec<QUICFrame>) -> HlsResult<()> {
        self.send_ack(QUICFlag::new_short(PacketType::ShortHeader))?;
        let pd_len = streams.iter().map(|s| s.len()).sum::<usize>();
        let mut packet = Self::build_packet(self.seq, &self.dcid, &self.token, PacketType::ShortHeader, pd_len);
        packet.encode()?;
        let (offset, encrypted) = self.conn.build_message(packet, streams, &mut self.uw_buffer).unwrap();
        self.socket.send_to(encrypted, self.addr)?;
        self.uw_buffer.reset();
        self.sent_num.insert(self.seq, offset);
        self.seq += 1;
        Ok(())
    }
}


impl StreamHandle for QUICStreamS {
    fn stream_param(&mut self) -> (&Buffer, StreamParam<'_>) {
        (&self.tr_buffer, StreamParam {
            handshake_finish: &mut self.handshake_finish,
            encrypted_channel: &mut self.encrypted_channel,
            hello_retrying: &mut self.hello_retrying,
            write_buffer: &mut self.tw_buffer,
            conn: self.conn.tls_conn(),
        })
    }
}
