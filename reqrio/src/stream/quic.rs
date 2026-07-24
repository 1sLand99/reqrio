use crate::error::HlsResult;
use crate::HlsError;
use reqtls::quic::*;
use reqtls::{rand, Buf, Buffer, ClientConfig, PacketType, StreamHandle, StreamParam};
use std::collections::HashMap;
use std::io::Write;
use std::mem;
use std::net::{SocketAddr, UdpSocket};
use std::ops::Range;

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
        let session = config.session.clone().unwrap_or_default();
        let key_log = config.key_log.clone();
        let mut stream = QUICStreamS {
            socket,
            ur_buffer: [0; 1500],
            uw_buffer: Buffer::with_capacity(15000),
            frame_buffer: QUICBuffer::with_capacity(1500),
            tw_buffer: Buffer::with_capacity(16438),
            conn: QUICConnection::new_client(session, key_log),
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


#[cfg(test)]
mod tests {
    use crate::stream::quic::QUICStreamS;
    use reqtls::{Buffer, ClientConfig, KeyExchangeAlg, Message, RecordType, RsaKey, TlsFinger, Version, WriteExt, ALPN};
    use std::fs;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};

    #[test]
    fn test_udp_stream() {
        Buffer::check_subscription(fs::read_to_string("../TOKEN").unwrap()).unwrap();
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(23, 214, 95, 199), 443));
        let config = ClientConfig {
            sni: "img-s-msn-com.akamaized.net",
            alpn: &ALPN::Http30,
            fingerprint: &mut TlsFinger::Default,
            client_cert: &mut vec![],
            cert_key: &RsaKey::none(),
            verify: false,
            ca_certs: &[],
            key_log: None,
            session: &None,
        };
        let mut stream = QUICStreamS::connect(socket, addr, config).unwrap();
        // let client_hello = hex::decode("010006eb030328a2c7592c0d40d3012ee51d3c4b0fed26725d8a3cff5016ec13c60bc6ae0bee000006130113021303010006bc0039005c200480010000110c00000001aafaeaba00000001712704800333d5040480f000000704806000000f00d8277593fbc5055c0c4e5ed87d023f818a41a1b9690604806000000104800075300902406705048060000008024064030245c000000020001e00001b696d672d732d6d736e2d636f6d2e616b616d61697a65642e6e6574002d00020101fe0d00fa00000100015d00209f5bc77f30e5e2f83e579fe61e5f980cb311caebbce0f068476f35de1911574800d017422554c533ae43c678285493de11fb8f4c40b38dff43fc6319eb75ce1305c6f574134eb01a9925832304b031a23d732ee66ba9416d09fc2f528886942aa32ab0feffb3bd93cecce3a5a4f65aaf16009c1de869f0f2925f04b8417fe6b5a8bdfef5c639d26819d8f7d143b83186540f7ca64c13720d9dd9f10fd6c736dd0b9c00ed9d9cdf0fdb9f70c29672ea824356c9c703564f4e4a0d225443d86a2d18f685bfbb88164b623ee522b9ad719b23d25f82c8a1da234dc5acb3d8e7131d0c471f7c1a9a5115d51e4ab14302a3d4b0ce44cd00050003026833002b0003020304003304ea04e811ec04c0f7303d38fa062bccabcc6091bc6a0a11a6a7b9b37e2b1abb66119ca9d9c073f01408631e91e8bcc4fa201b3a126d0c3b362416fd1b18013817bd196a0d504f648238298c3448d6032ef188b6d4ac30f43316a3ab4089a0b33058c851621fca5ee3162ec2aa6a9a63779de56bde957f3191bd7ec150542719d78914657b037b036181122371c4cead8b620f1320d4d2051256a2493b1bb3f645ae724ceb2550ee2c5cf2931dea96cdb85b67b1b23bb60086c68c24cf6574203133d408363fba7052d9c1031517aaa31c32bc4a3ec92cab3239a5259ef8499a4fa15584330fb8f65d78f72e63a74fe8a86f3d14a64be686d2652336c8af194030cb30cc9d163a633b647e456e4be71755eac60940c82e538a9fb98f74552abc5c61f4ac3237462a2b74943e090b9f24c73f8a8ff4029a82560b90d761eed8194e65ab291c324218c0e4102b9e9a4cfd71936a998182bb93f2e9a477c026285c6c731454b7003cce858bf4519547fab842106abed071ed5a3e288808bcf07f3033a1b6931580a61bbacc6df2915436cc98a9d3a7ec809d03978bdabc0d8cb8757a627c712482e0535efe388fbfd9605795383f3077144240c0505a8f88a1954b9850002a8e9817be119356b71fda72091b6b19a937868b2807660b662d6a209506225ed34974f11a16d212238c13a4b793a36545fac00ecc993ea427190178bda1f765bc1c29d6c0442d019ce596b2141300f5c244d91b686b8b4c47a27fda136ad87965d2e739a1952165a4cc1f33236eac04abb39f053379ed0914863a2931682d18521eff06801dc13518b30e12558483427eca147e357077e8cab9388c9fad93af7a025d764ba943b7b66b0c4ee672bee1a457c884cfce58c3e441671f9c5c006425861555c3f67181b154fb62920175494582574ff2b6385032a7978cb2a6ad1f97cf1393014035620c4682a49033a8179a0e085c456341599b708e88805666c9007bc428ba87932b7893e86b5726229a769710c26b8bd4955cd136eba90c32e61afe3753b529ccb5e85a72b3b407a5bc80e2aeef80b353e072efb971c137157fea94ba313c51fa5e9437420bf23d95f4a0ce89342dd537b02160445508571653f1c293977b5cb83c6627f427eab9038f350010d810f64583017a88a8297672796fed6838e979730b46acef2cab0bd79f50977d52d1b50e531457b3c02b169114d5559d10ad14651a811375277962e81099cd8152a8224db67a6febd4ca8d978d15d601d97c425b01581f665b19a224f2c40d49b0583936356b5a87e0108bc1ca7bd44863829b6efa503d8de561e8a06c20d2710099251b970d09729c49d2617a991f6eb0931ca0301e5059ce3b4cc02c18f7dcaddae887a35573ac3aac9b9596c3b223b0416bbfb35ef84876a2a87e06e6ad26aa1050874ffc9bc2b7303271503a6b395409c30a832b61ed823be805be6f778009d92f415bac25c956fe80b7aec15502f3c8b19c448b43c6df350abd4682347c95d7d06d00c7a4f9f4858d33742ab29a1fc70422428d4e71c843982d30b85a09908ef8c92bcd6781dd672dd54a5fef42a134988d9916a73900833f500cfedc4e178076b5496d76156fe77923df924f0855ba1bdd5b61f849ab7be2fd4487a2e9efb080500cd261091682d6ff95fd5570896a40f9ccf6fd8f765d06d538c4d05849e7be4e05dd8ffdce51f9a086cacdd5fe25001d0020b936d85710d918211c16c8d00a7f6e6426383bc524629da6da7897de366c187c000a000a000811ec001d00170018000d00140012040308040401050308050501080606010201001b0003020002001000050003026833").unwrap();
        // stream.write_all(&client_hello).unwrap();
        stream.read_frames().unwrap();
        stream.read_frames().unwrap();
        stream.read_frames().unwrap();
        let mut filled = stream.frame_buffer.flush().unwrap();
        let message = Message::from_reader(&mut filled, &RecordType::HandShake, KeyExchangeAlg::NULL, &Version::TLS_1_3).unwrap();
        println!("{:#?}", message);
        // stream.read_frames().unwrap();
    }
}