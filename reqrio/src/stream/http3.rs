use crate::error::HlsResult;
use crate::pack::{PackError, QPackDecode, QPackEncode, QPackType};
use crate::packet::HeaderParam;
use crate::request::RequestBuffer;
use crate::stream::ConnParam;
use crate::*;
use reqtls::quic::{QUICFrame, QUICFrameFlag};
use reqtls::{quic, Buf, Buffer, BufferError, ClientConfig, PacketType, QUICFlag, ReadExt, Reader, RlsError, WriteExt};
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::net::UdpSocket;

#[derive(Debug)]
pub struct H3Setting {
    flag: u64,
    value: u64,
}
#[allow(non_upper_case_globals)]
impl H3Setting {
    pub const MaxTableCapacity: u64 = 0x01;
    pub const MaxFieldSectionSize: u64 = 0x06;
    pub const BlockedStreams: u64 = 0x07;
    pub const EnableDatagram: u64 = 0x33;

    pub fn new(flag: u64, value: u64) -> H3Setting {
        H3Setting { flag, value }
    }

    pub fn from_reader(reader: &mut Reader) -> Result<H3Setting, BufferError> {
        Ok(H3Setting {
            flag: quic::read_variant(reader)? as u64,
            value: quic::read_variant(reader)? as u64,
        })
    }

    pub fn len(&self) -> usize {
        quic::variant_len(self.flag as usize) + quic::variant_len(self.value as usize)
    }

    pub fn write_to<W: WriteExt>(&self, writer: &mut W) -> Result<(), BufferError> {
        quic::write_variant(self.flag as usize, writer)?;
        quic::write_variant(self.value as usize, writer)
    }
}


#[repr(u64)]
pub enum H3Frame<'a> {
    Data(Buf<'a>)= 0x0,
    Settings(Vec<H3Setting>)= 0x4,
    PriorityUpdate {
        stream_id: u64,
        value: &'a str,
    }= 0xf0700,
    Headers(Buf<'a>)= 0x1,
    Reserved {
        typ: u64,
        payload: Buf<'a>,
    },
}
impl<'a> H3Frame<'a> {
    pub fn from_reader(reader: &mut Reader<'a>) -> Result<H3Frame<'a>, BufferError> {
        let typ = quic::read_variant(reader)? as u64;
        let len = quic::read_variant(reader)?;
        if reader.unread_len() < len { return Err(BufferError::Insufficient); }
        let mut reader = reader.read_reader(len)?;
        match typ {
            0x0 => Ok(H3Frame::Data(Buf::Ref(reader.read_slice(len)?))),
            0x1 => Ok(H3Frame::Headers(Buf::Ref(reader.read_slice(len)?))),
            0x4 => {
                let mut settings = vec![];
                while reader.unread_len() > 0 {
                    let setting = H3Setting::from_reader(&mut reader)?;
                    settings.push(setting);
                }
                Ok(H3Frame::Settings(settings))
            }
            0xf0700 => {
                let pos = reader.position();
                let stream_id = quic::read_variant(&mut reader)? as u64;
                let sid_len = reader.position() - pos;
                Ok(H3Frame::PriorityUpdate {
                    stream_id,
                    value: reader.read_str(len - sid_len)?,
                })
            }
            _ => Ok(H3Frame::Reserved {
                typ,
                payload: Buf::Ref(reader.read_slice(len)?),
            })
        }
    }

    pub fn write_to<W: WriteExt>(&self, writer: &mut W) -> Result<(), BufferError> {
        match self {
            H3Frame::Data(data) => {
                quic::write_variant(0x0, writer)?;
                quic::write_variant(data.len(), writer)?;
                writer.write_slice(data.as_ref())
            }
            H3Frame::Settings(settings) => {
                quic::write_variant(0x4, writer)?;
                let len = settings.iter().map(|x| x.len()).sum::<usize>();
                quic::write_variant(len, writer)?;
                for setting in settings {
                    setting.write_to(writer)?;
                }
                Ok(())
            }
            H3Frame::PriorityUpdate {
                stream_id,
                value
            } => {
                quic::write_variant(0xf0700, writer)?;
                let len = quic::variant_len(*stream_id as usize) + value.len();
                quic::write_variant(len, writer)?;
                quic::write_variant(*stream_id as usize, writer)?;
                writer.write_slice(value.as_ref())
            }
            H3Frame::Headers(hdr) => {
                quic::write_variant(0x1, writer)?;
                quic::write_variant(hdr.len(), writer)?;
                writer.write_slice(hdr.as_ref())
            }
            H3Frame::Reserved { typ, payload } => {
                quic::write_variant(*typ as usize, writer)?;
                quic::write_variant(payload.len(), writer)?;
                writer.write_slice(payload.as_ref())
            }
        }
    }

    pub fn encode(&self, offset: usize) -> Result<Vec<u8>, BufferError> {
        let mut res = vec![0; 100];
        let mut writer = Buffer::from_ptr(res.as_mut_slice());
        if offset == 0 { writer.write_u8(0)?; }
        self.write_to(&mut writer)?;
        unsafe { res.set_len(writer.len()) };
        Ok(res)
    }
}

impl<'a> Debug for H3Frame<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            H3Frame::Data(pd) => write!(f, "Data({})", pd.len()),
            H3Frame::Settings(sts) => write!(f, "Settings({:?})", sts),
            H3Frame::PriorityUpdate { stream_id, value } => write!(f, "PriorityUpdate({}, {})", stream_id, value),
            H3Frame::Headers(hdrs) => write!(f, "Headers({})", hdrs.len()),
            H3Frame::Reserved { typ, payload } => write!(f, "Reserved({}, {})", typ, payload.len()),
        }
    }
}

#[derive(Debug)]
#[repr(u64)]
pub enum H3Stream {
    Control = 0x00,
    QPackEncoder = 0x02,
    QPackDecoder = 0x03,
    Reserved(u64),
    BidirectionalStream,
}

impl From<usize> for H3Stream {
    fn from(val: usize) -> H3Stream {
        match val {
            0x00 => H3Stream::Control,
            0x02 => H3Stream::QPackEncoder,
            0x03 => H3Stream::QPackDecoder,
            _ => H3Stream::Reserved(val as u64),
        }
    }
}

impl H3Stream {
    pub fn handle_stream<'a>(&self, reader: &mut Reader<'a>, decoder: &mut QPackDecode) -> Result<H3Frame<'a>, HlsError> {
        match self {
            H3Stream::QPackEncoder => {
                let item = decoder.decode_next(QPackType::StreamEncoder, &0, reader)?;
                println!("{:?}", item);
                Ok(H3Frame::Reserved { typ: 0, payload: Buf::Ref(&[]) })
            }
            H3Stream::QPackDecoder => {
                decoder.decode_next(QPackType::StreamDecoder, &0, reader)?;
                Ok(H3Frame::Reserved { typ: 0, payload: Buf::Ref(&[]) })
            }
            H3Stream::BidirectionalStream | H3Stream::Control => Ok(H3Frame::from_reader(reader)?),
            H3Stream::Reserved(val) => {
                Ok(H3Frame::Reserved {
                    typ: *val,
                    payload: Buf::Ref(reader.read_slice(reader.unread_len())?),
                })
            }
        }
    }
}

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
    max_stream: u64,
    sid: u64,
}

impl HTTP3StreamS {
    pub fn connect(mut conn: ConnParam) -> HlsResult<HTTP3StreamS> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        let addr = conn.url.addr().socket_addr(false)?;
        let mut quic = QUICStreamS::connect(socket, addr, ClientConfig::from(&mut conn)).unwrap();
        let mut writer = Buffer::with_capacity(100);
        writer.write_u8(0)?;
        H3Frame::Settings(vec![
            H3Setting::new(H3Setting::MaxTableCapacity, 65536),
            H3Setting::new(H3Setting::MaxFieldSectionSize, 262144),
            H3Setting::new(H3Setting::BlockedStreams, 100),
            H3Setting::new(H3Setting::EnableDatagram, 1),
            H3Setting::new(0x7c3b6e5b0, 4089453656)
        ]).write_to(&mut writer)?;
        H3Frame::Reserved {
            typ: 0x11d4c4c93c,
            payload: Buf::Ref(&[0x54]),
        }.write_to(&mut writer)?;

        let setting_frame = QUICFrame::Stream {
            flag: QUICFrameFlag::new(0),
            sid: 2,
            offset: 0,
            payload: Buf::Ref(writer.filled()),
            buf_pos: 0..0,
        };
        quic.write_stream(vec![setting_frame])?;
        Ok(HTTP3StreamS {
            quic,
            stream_ids: Default::default(),
            encoder: QPackEncode::new(65536),
            decoder: QPackDecode::new(65536),
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
                        match setting.flag {
                            H3Setting::MaxTableCapacity => {
                                self.encoder.update_table_size(setting.value as usize);
                                self.decoder.update_table_size(setting.value as usize);
                            }
                            H3Setting::BlockedStreams => self.max_stream = setting.value,
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
        let mut buffer = Buffer::with_capacity(4096);
        let mut offset = 0;
        loop {
            buffer.reset();
            let len = reader::ReadExt::read(&mut request, &mut buffer)?;
            if len == 0 { break; }
            let chunks = buffer.filled().chunks(1100);
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