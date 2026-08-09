use std::cmp::max;
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
    ur_buffer: [u8; 1500],
    uw_buffer: Buffer,

    frame_buffer: QUICBuffer,
    tr_buffer: Buffer,
    tw_buffer: Buffer,
    conn: QUICConnection,
    sent: HashMap<u64, Range<usize>>,
    largest_ack: u64,

    addr: SocketAddr,
    seq: u64,
    dcid: Buf<'static>,

    handshake_finish: bool,
    encrypted_channel: bool,
    hello_retrying: bool,

}

struct QUICAck<'a> {
    flag: QUICFlag,
    conn: &'a mut QUICConnection,
    largest_ack: &'a mut u64,
    uw_buffer: &'a mut Buffer,
    dcid: &'a Buf<'static>,
    seq: &'a mut u64,
}

impl<'a> QUICAck<'a> {
    pub fn build(&mut self) -> HlsResult<&[u8]> {
        let max_num = self.conn.recv_nums().iter().max().cloned().unwrap_or(*self.largest_ack);
        *self.largest_ack = max(max_num, *self.largest_ack);
        let min_num = self.conn.recv_nums().iter().min().cloned().unwrap_or(*self.largest_ack);
        let sum = ((*self.largest_ack + min_num) * (*self.largest_ack - min_num + 1)) / 2;
        let recv_sum = self.conn.recv_nums().iter().sum::<u64>();
        let frame = QUICFrame::Ack {
            largest_acknowledged: *self.largest_ack,
            ack_delay: 1,
            ack_range_count: 0,
            first_ack_range: if sum != recv_sum || sum == *self.largest_ack { 0 } else { *self.largest_ack - min_num },
        };
        let packet = QUICPacket::new_ack(self.flag, self.dcid.as_ref(), *self.seq, frame.len());
        let offset = self.uw_buffer.offset();
        let (_, filled) = self.conn.build_message(packet, vec![frame], self.uw_buffer).unwrap();
        self.uw_buffer.reset_offset(offset);
        *self.seq += 1;
        Ok(filled)
    }
}

impl QUICStreamS {
    pub fn connect(socket: UdpSocket, remote_addr: SocketAddr, mut config: ClientConfig<'_>) -> HlsResult<QUICStreamS> {
        socket.set_read_timeout(Some(Duration::from_millis(3000))).unwrap();
        let session = config.session.clone().unwrap_or_default();
        let key_log = config.key_log.clone();
        let mut stream = QUICStreamS {
            socket,
            ur_buffer: [0; 1500],
            uw_buffer: Buffer::with_capacity(15000),
            frame_buffer: QUICBuffer::with_capacity(16438),
            tr_buffer: Buffer::with_capacity(1500),
            tw_buffer: Buffer::with_capacity(16438),
            conn: QUICConnection::new(session, key_log),
            sent: HashMap::new(),
            largest_ack: 0,
            addr: remote_addr,
            seq: 1,
            dcid: Buf::Vec(rand::random::<[u8; 8]>().to_vec()),
            handshake_finish: false,
            encrypted_channel: false,
            hello_retrying: false,
        };
        stream.conn.make_initial_cipher(&stream.dcid, false).unwrap();
        stream.handle_client_hello(&mut config).unwrap();
        stream.tw_buffer.used_empty(5);
        stream.write_buffer(PacketType::Initial, None).unwrap();
        let mut config = Config::Client(config);
        while !stream.handshake_finish {
            stream.read_next_packet(false).unwrap();
            let Some(mut reader) = stream.frame_buffer.flush()else { continue };
            let mut read_len = 0;
            while let Ok(message) = Message::from_reader(&mut reader, &RecordType::HandShake, KeyExchangeAlg::NULL, &Version::TLS_1_3) {
                read_len += message.encoded.len();
                println!("{:#?}", message);
                let is_server_hello = message.parsed.server().is_some();
                QUICStreamS::handle_handshake(&mut StreamParam {
                    handshake_finish: &mut stream.handshake_finish,
                    encrypted_channel: &mut stream.encrypted_channel,
                    hello_retrying: &mut stream.hello_retrying,
                    write_buffer: &mut stream.tw_buffer,
                    conn: stream.conn.tls_conn(),
                }, Some(&mut config), message).unwrap();
                if is_server_hello {
                    stream.conn.make_sample_cipher(false).unwrap();
                }
            }
            stream.frame_buffer.read_size(read_len);
            if !stream.tw_buffer.is_empty() {
                stream.write_buffer(PacketType::Handshake, None).unwrap();
            }
        }
        stream.conn.tls_conn().make_cipher(false).unwrap();
        stream.conn.make_sample_cipher(false).unwrap();
        Ok(stream)
    }

    fn build_packet<'a>(seq: u64, dcid: &'a Buf<'a>, typ: PacketType, pd_len: usize) -> QUICPacket<'a> {
        match typ {
            PacketType::Initial | PacketType::Handshake => QUICPacket::new_long(typ, seq, pd_len, dcid.as_ref()),
            PacketType::ShortHeader => QUICPacket::new_short(typ, seq, pd_len, dcid.as_ref()),
        }
    }

    fn write_buffer(&mut self, typ: PacketType, buf: Option<&[u8]>) -> HlsResult<()> {
        let mut frames = vec![QUICFrame::Ping];
        let mut pd_len = 1;
        let buf = if let Some(buf) = buf { buf } else { self.tw_buffer.filled() };
        for (i, chunk) in buf.chunks(350).enumerate() {
            let frame = QUICFrame::Crypto {
                offset: i * 350,
                value: Buf::Ref(chunk),
            };
            pd_len += frame.len();
            frames.push(frame);
            if pd_len + 350 >= 1210 {
                let packet = Self::build_packet(self.seq, &self.dcid, typ, mem::take(&mut pd_len));
                let (offset, filled) = self.conn.build_message(packet, mem::take(&mut frames), &mut self.uw_buffer).unwrap();
                self.socket.send_to(filled, self.addr).unwrap();
                self.sent.insert(self.seq, offset);
                self.seq += 1;
            }
        }
        if !frames.is_empty() {
            let packet = Self::build_packet(self.seq, &self.dcid, typ, mem::take(&mut pd_len));
            let (offset, filled) = self.conn.build_message(packet, mem::take(&mut frames), &mut self.uw_buffer).unwrap();
            self.socket.send_to(filled, self.addr).unwrap();
            self.sent.insert(self.seq, offset);
            self.seq += 1;
        }
        self.tw_buffer.reset();
        Ok(())
    }

    pub fn read_next_packet(&mut self, server: bool) -> HlsResult<Vec<QUICFrame<'_>>> {
        let len = self.socket.recv(&mut self.ur_buffer).unwrap();
        let mut reader = Reader::from_slice(&self.ur_buffer[..len]);
        let mut packet = QUICPacket::from_reader(&mut reader).unwrap();
        if packet.flag().packet_type() == PacketType::Initial {
            self.conn.make_initial_cipher(packet.dc_id(), server).unwrap();
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
                return Ok(vec![]);
            }
        };

        let mut reader = Reader::from_slice(&rb[..len]);
        let mut res = vec![];
        let mut need_ack = false;
        while reader.unread_len() > 0 {
            let frame = QUICFrame::from_reader(&mut reader).unwrap();
            println!("{:#?}", frame);
            if frame.need_ack() { need_ack = true; }
            match frame {
                QUICFrame::Ack { largest_acknowledged, first_ack_range, .. } => {
                    let start = largest_acknowledged - first_ack_range;
                    for large in start..=largest_acknowledged {
                        self.sent.remove(&large);
                    }
                }
                QUICFrame::ConnectionCloseTrp { reason, err_code, .. } => return Err(HlsError::Currently(format!("err: {:?}; reason: {}", err_code, reason))),
                QUICFrame::Crypto { offset, value } => self.frame_buffer.write_at(offset, value).unwrap(),
                QUICFrame::Ping => {}
                QUICFrame::Stream { .. } => res.push(frame),
                _ => {}
            }
        }
        if need_ack {
            let mut ack = QUICAck {
                flag: *packet.flag(),
                conn: &mut self.conn,
                largest_ack: &mut self.largest_ack,
                uw_buffer: &mut self.uw_buffer,
                dcid: &self.dcid,
                seq: &mut self.seq,
            };
            self.socket.send_to(ack.build().unwrap(), self.addr).unwrap();
        }
        Ok(res)
    }

    pub fn write_stream(&mut self, stream: QUICFrame) -> HlsResult<()> {
        let mut packet = Self::build_packet(self.seq, &self.dcid, PacketType::ShortHeader, stream.len());
        packet.encode().unwrap();
        println!("{:#?}", packet);
        let (offset, encrypted) = self.conn.build_message(packet, vec![stream], &mut self.uw_buffer).unwrap();
        self.socket.send_to(encrypted, self.addr).unwrap();
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