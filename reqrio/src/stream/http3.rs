use crate::error::HlsResult;
use crate::pack::{PackError, QPackDecode, QPackEncode, QPackType};
use crate::packet::{H3Frame, H3Setting, H3Stream, HeaderParam};
use crate::request::RequestBuffer;
use crate::stream::ConnParam;
use crate::*;
use reqtls::quic::{QUICFrame, QUICFrameFlag};
use reqtls::{quic, Buf, Buffer, BufferError, ClientConfig, PacketType, QUICFlag, ReadExt, Reader, RlsError, WriteExt};
use std::collections::HashMap;
use std::net::UdpSocket;


struct StreamParam {
    typ: H3Stream,
    fin: bool,
    last_offset: usize,
    buffer: Buffer,
}


pub struct HTTP3StreamS {
    quic: QUICStreamS,
    stream_ids: HashMap<u64, StreamParam>,
    encoder: QPackEncode,
    decoder: QPackDecode,
    write_buffer: Buffer,
    max_stream: u64,
    sid: u64,
}

impl HTTP3StreamS {
    pub fn connect(mut conn: ConnParam) -> HlsResult<HTTP3StreamS> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        let addr = conn.url.addr().socket_addr(false)?;
        let mut quic = QUICStreamS::connect(socket, addr, ClientConfig::from(&mut conn)).unwrap();
        let mut write_buffer = Buffer::with_capacity(4096);
        write_buffer.write_u8(0)?;
        for frame in &conn.fingerprint.h3().frames {
            frame.write_to(&mut write_buffer)?;
        }
        let setting_frame = QUICFrame::Stream {
            flag: QUICFrameFlag::new(0),
            sid: 2,
            offset: 0,
            payload: Buf::Ref(write_buffer.filled()),
            buf_pos: 0..0,
        };
        quic.write_stream(vec![setting_frame])?;
        write_buffer.reset();
        Ok(HTTP3StreamS {
            quic,
            stream_ids: Default::default(),
            encoder: QPackEncode::new(65536),
            decoder: QPackDecode::new(65536),
            write_buffer,
            max_stream: 100,
            sid: 0,
        })
    }


    pub fn recv(&mut self, responses: &mut HashMap<u64, Response>) -> HlsResult<Vec<u64>> {
        let mut res = vec![];
        self.quic.read_next_packet()?;
        self.quic.handle_queues(|sid, queues, buffers, | {
            let param = self.stream_ids.entry(*sid).or_insert_with(|| StreamParam {
                typ: H3Stream::BidirectionalStream,
                fin: false,
                last_offset: 0,
                buffer: Buffer::with_capacity(if sid & 0b10 == 0b10 { 1500 } else { 8192 }),
            });
            let pos = queues.iter().position(|x| x.offset == param.last_offset);
            let Some(pos) = pos else { return Ok(None) };
            let queue = queues.remove(pos);
            param.fin = param.fin || queue.fin;
            let (task_buffer, _) = &buffers[&queue.bid];
            param.buffer.check_move(queue.pos.len())?;
            param.last_offset += queue.pos.len();
            if param.buffer.unfilled_len() < queue.pos.len() {
                #[cfg(all(debug_assertions, feature = "log"))]
                warn!("[HTTP3] resize buffer = {}",param.buffer.capacity()*2);
                param.buffer.resize(queue.pos.len() - param.buffer.unfilled_len())?;
            }
            param.buffer.write_slice(task_buffer.slice(queue.pos))?;
            if param.buffer.is_empty() {
                if param.fin { res.push(*sid) }
                return Ok(Some(queue.bid));
            };
            let mut reader = Reader::from_slice(param.buffer.filled());
            if sid & 0b10 == 0b10 && queue.offset == 0 {
                param.typ = quic::read_variant(&mut reader)?.into();
            }
            #[cfg(feature = "log")]
            debug!("[HTTP3] recv quic: typ={:?}; sid={}; fin={}",param.typ, sid,  param.fin);
            let mut pos = reader.position();
            while reader.unread_len() > 0 {
                let frame = match param.typ.handle_stream(&mut reader, &mut self.decoder) {
                    Ok(frame) => frame,
                    Err(HlsError::Rls(RlsError::Buffer(BufferError::Insufficient))) => break,
                    Err(HlsError::Rls(RlsError::Buffer(BufferError::IndexOutBound { .. }))) => break,
                    Err(e) => return Err(e)
                };
                println!("{:#?}", frame);
                match frame {
                    H3Frame::Settings(settings) => for setting in settings {
                        match setting.flag() {
                            H3Setting::MaxTableCapacity => {
                                self.encoder.update_table_size(setting.value() as usize);
                                self.decoder.update_table_size(setting.value() as usize);
                            }
                            H3Setting::BlockedStreams => self.max_stream = setting.value(),
                            _ => {}
                        }
                    }
                    //客户端忽略，服务端暂不处理
                    H3Frame::PriorityUpdate { .. } => {}
                    H3Frame::Headers(hdr) => {
                        let Some(response) = responses.get_mut(sid) else { continue };
                        let read_size = match self.decoder.decode_into(hdr.as_ref(), response.header_mut(), QPackType::Stream, sid) {
                            Ok(size) => size,
                            Err(HlsError::HPack(PackError::BlockedStream(_))) => break,
                            Err(e) => return Err(e)
                        };
                        assert_eq!(read_size, hdr.len());
                        response.make_coding()?;
                    }
                    H3Frame::Data(body) => {
                        let Some(response) = responses.get_mut(sid) else { continue };
                        response.push_raw_slice(body.as_ref())?;
                    }
                    H3Frame::Reserved { .. } => {}
                }
                pos = reader.position();
            }
            param.buffer.used_empty(pos);
            if param.fin && param.buffer.is_empty() { res.push(*sid); }
            Ok(Some(queue.bid))
        })?;
        self.quic.send_ack(QUICFlag::new_short(PacketType::ShortHeader))?;
        Ok(res)
    }
    fn send_inner<'a>(&'a mut self, header: &Header, body: &Body<'_>, mut param: HeaderParam<'a>) -> HlsResult<u64> {
        param.q_sid = &self.sid;
        param.qpack_encoder = Some(&mut self.encoder);
        let mut request = RequestBuffer::new(header, body, param)?;
        let mut offset = 0;
        loop {
            self.write_buffer.reset();
            let len = reader::ReadExt::read(&mut request, &mut self.write_buffer)?;
            if len == 0 { break; }
            let chunks = self.write_buffer.filled().chunks(1100);
            let chunk_count = chunks.clone().count();
            for (i, chunk) in chunks.into_iter().enumerate() {
                let stream = QUICFrame::Stream {
                    flag: QUICFrameFlag::new(offset).with_fin(reader::ReadExt::wrote(&request) && i + 1 == chunk_count),
                    sid: self.sid,
                    offset,
                    payload: Buf::Ref(chunk),
                    buf_pos: 0..0,
                };
                let streams = if offset == 0 && let Some(priority) = header.get_str("priority") {
                    let frame = H3Frame::PriorityUpdate {
                        stream_id: self.sid,
                        value: priority,
                    };
                    vec![QUICFrame::Stream {
                        flag: QUICFrameFlag::new(44),
                        sid: 2,
                        offset: 44 + (self.sid as usize / 4) * 12,
                        payload: Buf::Vec(frame.encode(44)?),
                        buf_pos: 0..0,
                    }, stream]
                } else { vec![stream] };
                self.quic.write_stream(streams)?;
                offset += chunk.len();
            }
        }
        Ok(self.sid)
    }


    pub fn send(&mut self, header: &Header, body: &Body<'_>, param: HeaderParam<'_>) -> HlsResult<u64> {
        let sid = self.send_inner(header, body, param)?;
        self.sid += 4;
        Ok(sid)
    }

    pub fn shutdown_sync(&mut self) -> HlsResult<()> {
        Ok(())
    }
}