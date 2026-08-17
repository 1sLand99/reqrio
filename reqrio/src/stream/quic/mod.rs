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

pub struct QUICStreamS {
    socket: UdpSocket,
    ur_buffer: Buffer,
    ud_buffer: [u8; 1500],
    uw_buffer: Buffer,

    tw_buffer: Buffer,
    conn: QUICConnection,
    sent_num: HashMap<u64, Range<usize>>,
    pd_buffer: HashMap<u64, MapBuffer>,

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
}

struct QUICParams<'a> {
    dcid: &'a mut Buf<'static>,
    token: &'a mut Buf<'static>,
    conn: &'a mut QUICConnection,
    ur_buffer: &'a mut Buffer,
    ud_buffer: &'a mut [u8; 1500],
    pd_buffer: &'a mut HashMap<u64, MapBuffer>,
    sent_num: &'a mut HashMap<u64, Range<usize>>,
    packet_offsets: &'a mut Vec<(PacketType, Range<usize>)>,
    handshake_finish: &'a bool,
}


impl QUICStreamS {
    pub fn connect(socket: UdpSocket, remote_addr: SocketAddr, config: ClientConfig<'_>) -> Result<QUICStreamS, QUICError> {
        socket.set_read_timeout(Some(Duration::from_millis(3000)))?;
        let session = config.session.clone().unwrap_or_default();
        let key_log = config.key_log.clone();
        let mut pd_buffer = HashMap::new();
        pd_buffer.insert(0, MapBuffer::with_capacity(6000));
        QUICStreamS {
            socket,
            ur_buffer: Buffer::with_capacity(6000),
            ud_buffer: [0; 1500],
            uw_buffer: Buffer::with_capacity(15000),
            tw_buffer: Buffer::with_capacity(16438),
            conn: QUICConnection::new(session, key_log, config.verify),
            sent_num: HashMap::new(),
            pd_buffer,
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
        let buffer = self.pd_buffer.get_mut(&0).ok_or(QUICError::BufferNotInited)?;
        let Ok(mut reader) = buffer.read_reader() else { return Ok(()) };
        let mut read_len = 0;
        while let Ok(message) = Message::from_reader(&mut reader, &RecordType::HandShake, KeyExchangeAlg::NULL, &Version::TLS_1_3) {
            // println!("{:#?}", message);
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
                buffer.reset();
                return Ok(());
            }
        }
        buffer.flush(read_len)?;
        Ok(())
    }

    fn handshake(mut self, mut config: ClientConfig) -> Result<QUICStreamS, QUICError> {
        self.send_client_hello(&mut config, false)?;
        let mut config = Config::Client(config);
        while !self.handshake_finish {
            match self.read_next_packet() {
                Err(QUICError::InitialRetry) => {
                    self.crypto_offset = 0;
                    if let Some(b) = self.pd_buffer.get_mut(&0) { b.reset() }
                    self.ur_buffer.reset();
                    self.packet_offsets.clear();
                    self.current = PacketType::Initial;
                    let config = config.client_mut().ok_or("missing client config")?;
                    self.send_client_hello(config, true)?;
                    continue;
                }
                Err(e) => return Err(e),
                Ok(_) => {}
            };

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
        if let Some(buffer) = self.pd_buffer.get_mut(&0) { buffer.reset(); }
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

    pub fn read_next_packet(&mut self) -> Result<(Vec<u64>, &mut HashMap<u64, MapBuffer>), QUICError> {
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
                trace!("read flag={:?}; cur={:?}; {}", flag.packet_type(), self.current, flag.packet_type() > self.current);
                if flag.packet_type() > self.current {
                    self.packet_offsets.push((flag.packet_type(), off));
                    continue;
                }
                break off;
            }
        };
        Ok((QUICStreamS::handle_packet(QUICParams {
            dcid: &mut self.dcid,
            token: &mut self.token,
            conn: &mut self.conn,
            ur_buffer: &mut self.ur_buffer,
            ud_buffer: &mut self.ud_buffer,
            pd_buffer: &mut self.pd_buffer,
            sent_num: &mut self.sent_num,
            packet_offsets: &mut self.packet_offsets,
            handshake_finish: &self.handshake_finish,
        }, off)?, &mut self.pd_buffer))
    }

    fn handle_packet(mut params: QUICParams, mut off: Range<usize>) -> Result<Vec<u64>, QUICError> {
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
        let len = params.conn.read_message(&mut packet, &mut reader, params.ud_buffer).unwrap();
        assert_eq!(packet.len(), reader.position());
        let zero_len = reader.find(|&b| b != 0).unwrap_or(reader.unread_len());
        println!("1111111111={}-{:?}", zero_len, &reader.inner()[reader.position()..]);
        reader.read_slice(zero_len)?;
        off.start += reader.position();
        if !off.is_empty() {
            let flag = QUICFlag::from_raw(reader.inner()[reader.position()]);
            params.packet_offsets.insert(0, (flag.packet_type(), off));
        }
        QUICStreamS::handle_frames(&mut params, len)
    }

    fn handle_frames(params: &mut QUICParams, decrypted_len: usize) -> Result<Vec<u64>, QUICError> {
        let mut res = vec![];
        let mut reader = Reader::from_slice(&params.ud_buffer[..decrypted_len]);
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
                QUICFrame::Crypto { offset, value } => {
                    trace!("[QUIC Frame] off={}; pd={}; hf={}", offset, value.len(), params.handshake_finish);
                    if *params.handshake_finish { continue; }
                    let buffer = params.pd_buffer.entry(0).or_insert_with(|| MapBuffer::with_capacity(6000));
                    buffer.write_at(offset, value.as_ref())?
                }
                QUICFrame::Stream { flag, sid, offset, payload } => {
                    trace!("[QUIC Frame] fin={}; sid={}; off={}; pd={}", flag.fin(), sid, offset, payload.len());
                    let buffer = params.pd_buffer.entry(sid).or_insert_with(|| MapBuffer::with_capacity(3072));
                    buffer.write_at(offset, payload.as_ref())?;
                    if flag.fin() { res.push(sid); }
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
        Ok(res)
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
        (self.pd_buffer[&0].as_raw(), StreamParam {
            handshake_finish: &mut self.handshake_finish,
            encrypted_channel: &mut self.encrypted_channel,
            hello_retrying: &mut self.hello_retrying,
            write_buffer: &mut self.tw_buffer,
            conn: self.conn.tls_conn(),
        })
    }
}
