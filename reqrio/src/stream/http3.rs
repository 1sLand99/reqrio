use crate::error::HlsResult;
use crate::pack::{PackItem, QPackDecode, QPackEncode, QPackType};
use crate::packet::HeaderParam;
use crate::request::RequestBuffer;
use crate::stream::ConnParam;
use crate::{hex, Body, Header, HlsError, QUICStreamS, Response};
use reqtls::quic::{QUICBuffer, QUICFrame, QUICFrameFlag};
use reqtls::{quic, Buf, Buffer, ClientConfig, ReadExt, Reader, WriteExt};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::net::UdpSocket;

#[derive(Debug)]
pub struct H3Setting {
    flag: u64,
    value: u64,
}

impl H3Setting {
    pub const MAX_TABLE_CAPACITY: u64 = 0x01;
    pub const BLOCKED_STREAMS: u64 = 0x07;

    pub fn from_reader(reader: &mut Reader) -> Result<H3Setting, HlsError> {
        Ok(H3Setting {
            flag: quic::read_variant(reader)? as u64,
            value: quic::read_variant(reader)? as u64,
        })
    }
}


#[repr(u64)]
#[derive(Debug)]
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
    pub fn from_reader(reader: &mut Reader<'a>) -> Result<H3Frame<'a>, HlsError> {
        let typ = quic::read_variant(reader)? as u64;
        let len = quic::read_variant(reader)?;
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
                let len = quic::read_variant(&mut reader)?;
                let pos = reader.position();
                let stream_id = quic::read_variant(&mut reader)? as u64;
                let sid_len = reader.position() - pos;
                Ok(H3Frame::PriorityUpdate {
                    stream_id,
                    value: reader.read_str::<HlsError>(len - sid_len)?,
                })
            }
            _ => Ok(H3Frame::Reserved {
                typ,
                payload: Buf::Ref(reader.read_slice(len)?),
            })
        }
    }
}


#[repr(u64)]
#[derive(Debug)]
pub enum H3Stream<'a> {
    Control = 0x00,
    QPackEncoder = 0x02,
    QPackDecoder(Vec<PackItem>) = 0x03,
    Frame(H3Frame<'a>),
}

impl<'a> H3Stream<'a> {
    pub fn from_quic_stream(typ: Option<usize>, reader: &mut Reader<'a>, decoder: &mut QPackDecode) -> Result<H3Stream<'a>, HlsError> {
        Ok(match typ {
            Some(0x02) => {
                println!("{:x?}", reader.inner());
                while reader.unread_len() > 0 {
                    let item = decoder.decode_next(QPackType::StreamEncoder, &0, reader)?;
                    println!("item: {:?}", item);
                }
                H3Stream::QPackEncoder
            }
            Some(0x03) => H3Stream::QPackDecoder(vec![]),
            Some(_) => H3Stream::Frame(H3Frame::from_reader(reader)?),
            None => H3Stream::Frame(H3Frame::from_reader(reader)?),
        })
    }
}

struct StreamParam {
    typ: Option<usize>,
    buffer: QUICBuffer,
    fin: bool,
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
        let mut quic = QUICStreamS::connect(socket, addr, ClientConfig::from(&mut conn))?;
        let setting_frame = QUICFrame::Stream {
            flag: QUICFrameFlag::new(0),
            sid: 2,
            offset: 0,
            len: 44,
            payload: Buf::Vec(hex::decode("00041f018001000006800400000740643301c0000007c3b6e5b0c0000000f3c01c58c0000011d4c4c93c0154")?),
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
        let frames = self.quic.read_next_packet(false)?;
        let mut res = Vec::with_capacity(responses.len());
        for frame in frames {
            let QUICFrame::Stream { flag, sid, offset, payload, .. } = frame else { continue };
            let param = match self.stream_ids.entry(sid) {
                Entry::Occupied(v) => v.into_mut(),
                Entry::Vacant(v) => v.insert(StreamParam {
                    typ: None,
                    buffer: QUICBuffer::with_capacity(if sid & 0b10 == 0b10 { 1024 } else { 8192 }),
                    fin: false,
                })
            };
            if flag.fin() { param.fin = true; }
            param.buffer.write_at(offset, payload)?;
            if flag.fin() && param.buffer.raw_buffer().is_empty() { return Ok(vec![sid]); }
            let Some(mut reader) = param.buffer.flush()else { continue };

            if sid & 0b10 == 0b10 && param.typ.is_none() {
                param.typ = Some(quic::read_variant(&mut reader)?);
            }
            let mut pos = reader.position();
            while reader.unread_len() > 0 {
                let stream = H3Stream::from_quic_stream(param.typ, &mut reader, &mut self.decoder)?;
                println!("{:#?}", stream);
                let frame = match stream {
                    H3Stream::Control => continue,
                    H3Stream::Frame(frame) => frame,
                    H3Stream::QPackEncoder => continue,
                    H3Stream::QPackDecoder(_) => continue,
                };
                match frame {
                    H3Frame::Settings(settings) => for setting in settings {
                        match setting.flag {
                            H3Setting::MAX_TABLE_CAPACITY => {
                                self.encoder.update_table_size(setting.value as usize);
                                self.decoder.update_table_size(setting.value as usize);
                            }
                            H3Setting::BLOCKED_STREAMS => self.max_stream = setting.value,
                            _ => {}
                        }
                    }
                    //客户端忽略，服务端暂不处理
                    H3Frame::PriorityUpdate { .. } => {}
                    H3Frame::Headers(hdr) => {
                        let response = responses.get_mut(&sid).ok_or("response not inited")?;
                        let mut buf = hdr.as_ref().to_vec();
                        let mut buffer = Buffer::from_ptr(buf.as_mut_slice());
                        buffer.add_len(buf.len());
                        self.decoder.decode_into(&mut buffer, response.header_mut(), QPackType::Stream, &sid)?;
                        response.make_coding()?;
                    }
                    H3Frame::Data(body) => {
                        let response = responses.get_mut(&sid).ok_or("response not inited")?;
                        response.push_raw_slice(body.as_ref())?;
                    }
                    H3Frame::Reserved { .. } => {}
                }
                pos = reader.position();
            }
            let empty = param.buffer.read_size(pos);
            println!("{} {}", param.fin, empty);
            if param.fin && empty { res.push(sid); }
        }
        Ok(res)
    }
    fn send_inner<'a>(&'a mut self, header: &Header, body: &Body<'_>, mut param: HeaderParam<'a>) -> HlsResult<u64> {
        param.q_sid = &self.sid;
        param.qpack_encoder = Some(&mut self.encoder);

        let mut request = RequestBuffer::new(header, body, param)?;
        let mut buffer = Buffer::with_capacity(4096);
        let offset = 0;
        loop {
            buffer.reset();
            let len = crate::reader::ReadExt::read(&mut request, &mut buffer)?;
            if len == 0 { break; }
            let stream = QUICFrame::Stream {
                flag: QUICFrameFlag::new(offset).with_fin(crate::reader::ReadExt::wrote(&request)),
                sid: self.sid,
                offset,
                len,
                payload: Buf::Ref(buffer.filled()),
            };
            let streams = if offset == 0 && let Some(priority) = header.get_str("priority") {
                vec![QUICFrame::Stream {
                    flag: QUICFrameFlag::new(44),
                    sid: 2,
                    offset: 44,
                    len: priority.len(),
                    payload: Buf::Ref(priority.as_bytes()),
                }, stream]
            } else { vec![stream] };
            self.quic.write_stream(streams)?;
        }
        Ok(self.sid)
    }


    pub fn send(&mut self, header: &Header, body: &Body<'_>, param: HeaderParam<'_>) -> HlsResult<u64> {
        let sid = self.send_inner(header, body, param)?;
        self.sid += 4;
        Ok(sid)
    }
}