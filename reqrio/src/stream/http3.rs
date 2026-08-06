use crate::error::HlsResult;
use crate::pack::{HPackCoding, HPackItem};
use crate::packet::HeaderParam;
use crate::request::RequestBuffer;
use crate::stream::ConnParam;
use crate::{hex, Body, Fingerprint, Header, HlsError, QUICStreamS, Response};
use reqtls::quic::{QUICBuffer, QUICFrame, QUICFrameFlag};
use reqtls::{quic, Buf, Buffer, ClientConfig, ReadExt, Reader, Url};
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
            0x4 => {
                let mut settings = vec![];
                while let Ok(setting) = H3Setting::from_reader(&mut reader) {
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
    Control(H3Frame<'a>) = 0x00,
    QPackEncoder(Vec<HPackItem>) = 0x02,
    QPackDecoder(Vec<HPackItem>) = 0x03,
    Frame(H3Frame<'a>),
}

impl<'a> H3Stream<'a> {
    pub fn from_quic_stream(typ: Option<usize>, reader: &mut Reader<'a>, coder: &mut HPackCoding) -> Result<H3Stream<'a>, HlsError> {
        Ok(match typ {
            Some(0x02) => {
                //缓存数据
                H3Stream::QPackEncoder(coder.decoder().decode(reader.read_slice(reader.unread_len())?)?)
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
}


pub struct HTTP3StreamS {
    quic: QUICStreamS,
    stream_ids: HashMap<u64, StreamParam>,
    coder: HPackCoding,
    max_stream: u64,
    sid: u32,
}

impl HTTP3StreamS {
    pub fn connect(conn: ConnParam) -> HlsResult<HTTP3StreamS> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        let addr = conn.url.addr().socket_addr(false)?;
        let mut quic = QUICStreamS::connect(socket, addr, ClientConfig::from(conn))?;
        let setting_frame = QUICFrame::Stream {
            flag: QUICFrameFlag::new(0),
            sid: 2,
            offset: 0,
            len: 44,
            payload: Buf::Vec(hex::decode("00041f018001000006800400000740643301c0000007c3b6e5b0c0000000f3c01c58c0000011d4c4c93c0154")?),
        };
        quic.write_stream(setting_frame)?;
        quic.write_stream(QUICFrame::Stream {
            flag: QUICFrameFlag::new(44),
            sid: 2,
            offset: 44,
            len: 12,
            payload: Buf::Vec(hex::decode("800f07000700753d312c2069")?),
        })?;
        Ok(HTTP3StreamS {
            quic,
            stream_ids: Default::default(),
            coder: HPackCoding::new(65536),
            max_stream: 100,
            sid: 0,
        })
    }


    pub fn recv(&mut self, responses: &mut HashMap<u64, Response>) -> HlsResult<HashMap<u64, Response>> {
        let frames = self.quic.read_next_packet(false)?;
        let mut res = HashMap::with_capacity(responses.len());
        for frame in frames {
            let QUICFrame::Stream { flag, sid, offset, payload, .. } = frame else { continue };
            let param = match self.stream_ids.entry(sid) {
                Entry::Occupied(v) => v.into_mut(),
                Entry::Vacant(v) => v.insert(StreamParam {
                    typ: None, //if sid & 0b10 == 0b10 { Some(quic::read_variant(&mut reader)?) } else { None },
                    buffer: QUICBuffer::with_capacity(if sid & 0b10 == 0b10 { 1024 } else { 8192 }),
                })
            };
            param.buffer.write_at(offset, payload)?;
            let Some(mut reader) = param.buffer.flush()else { continue };
            if sid & 0b10 == 0b10 && param.typ.is_none() {
                param.typ = Some(quic::read_variant(&mut reader)?);
            }
            while let Ok(stream) = H3Stream::from_quic_stream(param.typ, &mut reader, &mut self.coder) {
                println!("{:#?}", stream);
                let frame = match stream {
                    H3Stream::Control(frame) => frame,
                    H3Stream::Frame(frame) => frame,
                    H3Stream::QPackEncoder(_) => continue,
                    H3Stream::QPackDecoder(_) => continue,
                };
                match frame {
                    H3Frame::Settings(settings) => for setting in settings {
                        match setting.flag {
                            H3Setting::MAX_TABLE_CAPACITY => {
                                self.coder.encoder().update_table_size(setting.value as usize);
                                self.coder.decoder().update_table_size(setting.value as usize);
                            }
                            H3Setting::BLOCKED_STREAMS => self.max_stream = setting.value,
                            _ => {}
                        }
                    }
                    //客户端忽略，服务端暂不处理
                    H3Frame::PriorityUpdate { .. } => {}
                    H3Frame::Headers(hdr) => {
                        let response = responses.get_mut(&sid).ok_or("response not inited")?;
                        self.coder.decoder().decode_into(hdr.as_ref(), response.header_mut())?;
                        response.make_coding()?;
                    }
                    H3Frame::Data(body) => {
                        let response = responses.get_mut(&sid).ok_or("response not inited")?;
                        response.push_raw_slice(body.as_ref())?;
                    }
                    H3Frame::Reserved { .. } => {}
                }
            }
            if flag.fin() && let Some(resp) = responses.remove(&sid) {
                res.insert(sid, resp);
            }
        }
        Ok(res)
    }

    pub fn send(&mut self, url: &Url, header: &mut Header, body: &Body<'_>, fingerprint: &Fingerprint) -> HlsResult<u64> {
        let sid = self.sid;
        self.sid += 4;
        let mut request = RequestBuffer::new(header, body, HeaderParam {
            url,
            encoder: self.coder.encoder(),
            stream_identifier: &sid,
            body_len: 0,
            priority: &fingerprint.h2().priority,
            weight: &fingerprint.h2().weight,
        })?;
        let mut buffer = Buffer::with_capacity(4096);
        let offset = 0;
        loop {
            buffer.reset();
            let len = crate::reader::ReadExt::read(&mut request, &mut buffer)?;
            println!("{}-{:?}", len, buffer.filled());
            if len == 0 { break; }
            let stream = QUICFrame::Stream {
                flag: QUICFrameFlag::new(offset).with_fin(crate::reader::ReadExt::wrote(&request)),
                sid: sid as u64,
                offset,
                len,
                payload: Buf::Ref(buffer.filled()),
            };
            self.quic.write_stream(stream)?;
        }
        Ok(sid as u64)
    }
}