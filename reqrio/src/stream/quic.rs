use crate::error::HlsResult;
use crate::HlsError;
use reqtls::quic::*;
use reqtls::{rand, Buf, Buffer, ClientConfig, Config, KeyExchangeAlg, Message, PacketType, RecordType, StreamHandle, StreamParam, Version, WriteExt};
use std::collections::HashMap;
use std::io::Write;
use std::mem;
use std::net::{SocketAddr, UdpSocket};
use std::ops::Range;
use std::time::Duration;

pub struct QUICStreamS {
    socket: UdpSocket,
    ur_buffer: [u8; 1500],
    uw_buffer: Buffer,

    frame_buffer: QUICBuffer,
    tw_buffer: Buffer,
    conn: QUICConnection,
    sent: HashMap<u64, Range<usize>>,
    addr: SocketAddr,
    seq: u64,
    dcid: Buf<'static>,

    handshake_finish: bool,
    encrypted_channel: bool,
    hello_retrying: bool,
}

impl QUICStreamS {
    pub fn connect(socket: UdpSocket, remote_addr: SocketAddr, mut config: ClientConfig<'_>) -> HlsResult<QUICStreamS> {
        socket.set_read_timeout(Some(Duration::from_millis(3000)))?;
        let session = config.session.clone().unwrap_or_default();
        let key_log = config.key_log.clone();
        let mut stream = QUICStreamS {
            socket,
            ur_buffer: [0; 1500],
            uw_buffer: Buffer::with_capacity(15000),
            frame_buffer: QUICBuffer::with_capacity(16438),
            tw_buffer: Buffer::with_capacity(16438),
            conn: QUICConnection::new(session, key_log),
            sent: HashMap::new(),
            addr: remote_addr,
            seq: 1,
            dcid: Buf::Vec(rand::random::<[u8; 8]>().to_vec()),
            handshake_finish: false,
            encrypted_channel: false,
            hello_retrying: false,
        };
        stream.conn.make_cipher(&stream.dcid, false)?;
        stream.handle_client_hello(&mut config)?;
        stream.tw_buffer.used_empty(5);
        stream.write_buffer(PacketType::Initial, None)?;
        let mut config = Config::Client(config);
        while !stream.handshake_finish {
            stream.read_frames().unwrap();
            let Some(mut reader) = stream.frame_buffer.flush()else { continue };
            let message = Message::from_reader(&mut reader, &RecordType::HandShake, KeyExchangeAlg::NULL, &Version::TLS_1_3).unwrap();
            println!("{:#?}", message);
            let is_server_hello = message.parsed.server().is_some();
            QUICStreamS::handle_handshake(&mut StreamParam {
                handshake_finish: &mut stream.handshake_finish,
                encrypted_channel: &mut stream.encrypted_channel,
                hello_retrying: &mut stream.hello_retrying,
                write_buffer: &mut stream.tw_buffer,
                conn: stream.conn.tls_conn(),
            }, Some(&mut config), message).unwrap();
            stream.frame_buffer.reset();
            if is_server_hello { stream.conn.make_sample_cipher(false).unwrap(); }
            if !stream.tw_buffer.is_empty() { stream.write_buffer(PacketType::Handshake, None).unwrap(); }
        }
        Ok(stream)
    }

    fn build_packet<'a>(seq: u64, dcid: &'a Buf<'a>, typ: PacketType, pd_len: usize) -> QUICPacket<'a> {
        match typ {
            PacketType::Initial => QUICPacket::new_initial(seq, pd_len, dcid.as_ref()),
            PacketType::Handshake => QUICPacket::default()
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
                let (offset, filled) = self.conn.build_message(packet, mem::take(&mut frames), &mut self.uw_buffer)?;
                self.socket.send_to(filled, self.addr)?;
                self.sent.insert(self.seq, offset);
                self.seq += 1;
            }
        }
        if !frames.is_empty() {
            let packet = Self::build_packet(self.seq, &self.dcid, typ, mem::take(&mut pd_len));
            let (offset, filled) = self.conn.build_message(packet, mem::take(&mut frames), &mut self.uw_buffer)?;
            self.socket.send_to(filled, self.addr)?;
            self.sent.insert(self.seq, offset);
            self.seq += 1;
        }
        self.tw_buffer.reset();
        Ok(())
    }

    fn read_frames(&mut self) -> HlsResult<()> {
        let len = self.socket.recv(&mut self.ur_buffer)?;
        println!("{}", len);
        let frames = self.conn.read(&self.ur_buffer[..len], false)?;
        println!("{:#?}", frames);
        let mut res = vec![];
        for frame in frames {
            match frame {
                QUICFrame::Ack { largest_acknowledged, first_ack_range, .. } => {
                    let start = largest_acknowledged - first_ack_range;
                    for large in start..=largest_acknowledged {
                        self.sent.remove(&large);
                    }
                }
                QUICFrame::ConnectionCloseTrp { reason, err_code, .. } => return Err(HlsError::Currently(format!("err: {:?}; reason: {}", err_code, reason))),
                QUICFrame::Crypto { offset, value } => self.frame_buffer.write_at(offset, value)?,
                QUICFrame::Ping => {}
                _ => res.push(frame)
            }
        }
        println!("{:?}", self.sent);
        Ok(())
    }
}

impl Write for QUICStreamS {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.write_buffer(PacketType::Initial, Some(buf))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
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