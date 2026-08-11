use crate::error::HlsResult;
use crate::HlsError;
use reqtls::quic::*;
use reqtls::*;
use std::collections::HashMap;
use std::mem;
use std::net::{SocketAddr, UdpSocket};
use std::ops::Range;
use std::time::Duration;

pub struct QUICStreamS {
    socket: UdpSocket,
    ur_buffer: Buffer,
    uw_buffer: Buffer,

    frame_buffer: QUICBuffer,
    tr_buffer: Buffer,
    tw_buffer: Buffer,
    conn: QUICConnection,
    sent: HashMap<u64, Range<usize>>,

    addr: SocketAddr,
    seq: u64,
    dcid: Buf<'static>,
    token: Buf<'static>,

    handshake_finish: bool,
    encrypted_channel: bool,
    hello_retrying: bool,
    crypto_offset: usize,

}

struct QUICAck<'a> {
    flag: QUICFlag,
    conn: &'a mut QUICConnection,
    uw_buffer: &'a mut Buffer,
    dcid: &'a Buf<'static>,
    seq: &'a mut u64,
}


impl<'a> QUICAck<'a> {
    pub fn build(&mut self) -> HlsResult<&[u8]> {
        self.conn.recv_nums_mut().sort();
        println!("{:?}", self.conn.recv_nums());
        let max_range = self.conn.recv_nums().max_range().ok_or("call recv first")?;
        let mut ack_range = Vec::with_capacity(self.conn.recv_nums().count() - 1);
        let remain = self.conn.recv_nums().count() - 1;
        let mut pre_start = max_range.start;
        for i in 0..remain {
            let r = self.conn.recv_nums().get(remain - i - 1);
            ack_range.push(AckRange {
                gap: pre_start - r.end - 2,
                range: r.end - r.start,
            });
            pre_start = r.start;
            // while ack_range.len() > 2 { ack_range.remove(ack_range.len() - 1); }
        }
        let frame = QUICFrame::Ack {
            largest_acknowledged: max_range.end,
            ack_delay: 1,
            ack_range_count: ack_range.len(),
            first_ack_range: max_range.end - max_range.start,
            ack_range,
        };
        // println!("send_ack={:#?}", frame);
        let packet = QUICPacket::new_ack(self.flag, self.dcid.as_ref(), *self.seq, frame.len());
        let offset = self.uw_buffer.offset();
        let (_, filled) = self.conn.build_message(packet, vec![frame], self.uw_buffer)?;
        self.uw_buffer.reset_offset(offset);
        *self.seq += 1;
        Ok(filled)
    }
}

impl QUICStreamS {
    pub fn connect(socket: UdpSocket, remote_addr: SocketAddr, config: ClientConfig<'_>) -> HlsResult<QUICStreamS> {
        socket.set_read_timeout(Some(Duration::from_millis(3000)))?;
        let session = config.session.clone().unwrap_or_default();
        let key_log = config.key_log.clone();
        QUICStreamS {
            socket,
            ur_buffer: Buffer::with_capacity(1500),
            uw_buffer: Buffer::with_capacity(15000),
            frame_buffer: QUICBuffer::with_capacity(16438),
            tr_buffer: Buffer::with_capacity(1500),
            tw_buffer: Buffer::with_capacity(16438),
            conn: QUICConnection::new(session, key_log, config.verify),
            sent: HashMap::new(),
            addr: remote_addr,
            seq: 1,
            dcid: Buf::Vec(rand::random::<[u8; 8]>().to_vec()),
            token: Buf::Ref(&[]),
            handshake_finish: false,
            encrypted_channel: false,
            hello_retrying: false,
            crypto_offset: 0,
        }.handshake(config)
    }

    fn handshake(mut self, mut config: ClientConfig) -> HlsResult<QUICStreamS> {
        self.conn.make_initial_cipher(&self.dcid, false, false)?;
        self.handle_client_hello(&mut config)?;
        self.tw_buffer.used_empty(5);
        self.write_buffer(PacketType::Initial, None)?;
        let mut config = Config::Client(config);
        while !self.handshake_finish {
            if let Err(e) = self.read_next_packet(false) {
                if e.to_string().contains("quic retry") {
                    // stream.tw_buffer.reset();
                    let config = config.client_mut().ok_or("missing client config")?;
                    self.crypto_offset = 0;
                    self.conn.quic_retry(config.session.clone().unwrap_or_default(), config.key_log.clone(), config.verify);
                    assert!(self.tw_buffer.is_empty());
                    self.conn.make_initial_cipher(&self.dcid, false, true)?;
                    self.handle_client_hello(config)?;
                    self.tw_buffer.used_empty(5);
                    self.write_buffer(PacketType::Initial, None)?;
                    continue;
                }
                return Err(e);
            };
            self.send_ack(QUICFlag::new_long(PacketType::Handshake))?;
            let Some(mut reader) = self.frame_buffer.flush()else { continue };
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
                }, Some(&mut config), message).unwrap();
                if is_server_hello && !self.hello_retrying {
                    self.conn.make_sample_cipher(false)?;
                }
            }
            self.frame_buffer.read_size(read_len);
            if !self.tw_buffer.is_empty() {
                self.send_ack(QUICFlag::new_long(PacketType::Handshake))?;
                if self.hello_retrying { self.tw_buffer.used_empty(5); } else { self.crypto_offset = 0; }
                println!("{}-{:?}", self.crypto_offset, self.tw_buffer.filled());
                self.write_buffer(if self.hello_retrying { PacketType::Initial } else { PacketType::Handshake }, None)?;
            }
        }
        self.conn.tls_conn().make_cipher(false)?;
        self.conn.make_sample_cipher(false).unwrap();
        Ok(self)
    }

    fn build_packet<'a>(seq: u64, dcid: &'a Buf<'a>, token: &'a Buf<'a>, typ: PacketType, pd_len: usize) -> QUICPacket<'a> {
        match typ {
            PacketType::Initial | PacketType::Handshake => QUICPacket::new_long(typ, seq, pd_len, dcid.as_ref(), token),
            PacketType::ShortHeader => QUICPacket::new_short(typ, seq, pd_len, dcid.as_ref()),
            PacketType::Retry => unreachable!(),
        }
    }

    pub fn send_ack(&mut self, flag: QUICFlag) -> Result<(), HlsError> {
        if self.conn.recv_nums().is_empty() { return Ok(()); }
        let mut ack = QUICAck {
            flag,
            conn: &mut self.conn,
            uw_buffer: &mut self.uw_buffer,
            dcid: &self.dcid,
            seq: &mut self.seq,
        };
        self.socket.send_to(ack.build()?, self.addr)?;
        self.conn.recv_nums_mut().clear();
        Ok(())
    }

    fn write_buffer(&mut self, typ: PacketType, buf: Option<&[u8]>) -> HlsResult<()> {
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
                self.sent.insert(self.seq, offset);
                self.seq += 1;
            }
        }
        if !frames.is_empty() {
            let packet = Self::build_packet(self.seq, &self.dcid, &self.token, typ, mem::take(&mut pd_len));
            let (offset, filled) = self.conn.build_message(packet, mem::take(&mut frames), &mut self.uw_buffer)?;
            self.socket.send_to(filled, self.addr).unwrap();
            self.sent.insert(self.seq, offset);
            self.seq += 1;
        }
        self.tw_buffer.reset();
        Ok(())
    }

    pub fn read_next_packet(&mut self, server: bool) -> HlsResult<Vec<QUICFrame<'_>>> {
        if self.ur_buffer.is_empty() || self.ur_buffer.filled()[0] == 0 {
            self.ur_buffer.reset();
            let len = self.socket.recv(self.ur_buffer.unfilled())?;
            if len == 0 { return Err(HlsError::PeerClosedConnection); }
            self.ur_buffer.add_len(len);
        }
        let mut reader = Reader::from_slice(self.ur_buffer.filled());
        let mut packet = QUICPacket::from_reader(&mut reader).unwrap();
        if packet.flag().packet_type() == PacketType::Initial {
            self.conn.make_initial_cipher(packet.dc_id(), server, false).unwrap();
        } else if packet.flag().packet_type() == PacketType::Retry {
            self.token = Buf::Vec(packet.token().to_vec());
            self.dcid = Buf::Vec(packet.sc_id().to_vec());
            self.ur_buffer.reset();
            return Err("quic retry".into());
        }
        if self.dcid.as_ref() != packet.sc_id().as_ref() && !packet.sc_id().as_ref().is_empty() {
            self.dcid = Buf::Vec(packet.sc_id().as_ref().to_vec());
        }
        let rb = self.tr_buffer.unfilled();
        let len = match self.conn.read_message(&mut packet, &mut reader, rb) {
            Ok(len) => len,
            Err(_e) => {
                #[cfg(feature = "log")]
                warn!("DecryptError: err={}; num={}; typ: {:?}", _e, packet.num(), packet.flag().packet_type());
                self.ur_buffer.reset();
                return Ok(vec![]);
            }
        };
        assert_eq!(packet.len(), reader.position());
        let mut reader = Reader::from_slice(&rb[..len]);
        let mut res = vec![];
        while reader.unread_len() > 0 {
            let frame = QUICFrame::from_reader(&mut reader).unwrap();
            match frame {
                QUICFrame::Ack { largest_acknowledged, first_ack_range, .. } => {
                    let start = largest_acknowledged - first_ack_range;
                    for large in start..=largest_acknowledged {
                        self.sent.remove(&large);
                    }
                }
                QUICFrame::ConnectionCloseTrp { reason, err_code, .. } => return Err(HlsError::Currently(format!("err: {:?}; reason: {}", err_code, reason))),
                QUICFrame::Crypto { offset, value } => self.frame_buffer.write_at(offset, value.as_ref()).unwrap(),
                QUICFrame::Ping => {}
                QUICFrame::Stream { .. } => res.push(frame),
                _ => {}
            }
        }
        self.ur_buffer.used_empty(packet.len());
        Ok(res)
    }

    pub fn write_stream(&mut self, streams: Vec<QUICFrame>) -> HlsResult<()> {
        self.send_ack(QUICFlag::new_short(PacketType::ShortHeader))?;
        let pd_len = streams.iter().map(|s| s.len()).sum::<usize>();
        let mut packet = Self::build_packet(self.seq, &self.dcid, &self.token, PacketType::ShortHeader, pd_len);
        packet.encode()?;
        let (offset, encrypted) = self.conn.build_message(packet, streams, &mut self.uw_buffer).unwrap();
        self.socket.send_to(encrypted, self.addr)?;
        self.sent.insert(self.seq, offset);
        self.seq += 1;
        Ok(())
    }
}


impl StreamHandle for QUICStreamS {
    fn stream_param(&mut self) -> (&mut Buffer, StreamParam<'_>) {
        (self.frame_buffer.raw_buffer_mut(), StreamParam {
            handshake_finish: &mut self.handshake_finish,
            encrypted_channel: &mut self.encrypted_channel,
            hello_retrying: &mut self.hello_retrying,
            write_buffer: &mut self.tw_buffer,
            conn: self.conn.tls_conn(),
        })
    }
}
