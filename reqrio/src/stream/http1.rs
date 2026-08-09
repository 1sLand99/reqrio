use crate::error::HlsResult;
use crate::packet::HeaderParam;
use crate::reader::ReadExt;
use crate::request::RequestBuffer;
use crate::stream::Stream;
use crate::{Body, Fingerprint, Header, Response};
use reqtls::{Buffer, Url};
use std::collections::HashMap;

pub struct HTTP1StreamS {
    write_buffer: Buffer,
    read_buffer: Buffer,
    stream: Stream,
    send_sid: u64,
    recv_sid: u64,
}


impl HTTP1StreamS {
    pub fn new(stream: Stream) -> HTTP1StreamS {
        HTTP1StreamS {
            write_buffer: Buffer::with_capacity(16384),
            read_buffer: Buffer::with_capacity(16438),
            stream,
            send_sid: 0,
            recv_sid: 0,
        }
    }

    pub fn send(&mut self, url: &Url, header: &Header, body: &Body<'_>, fingerprint: &Fingerprint) -> HlsResult<u64> {
        let sid = self.send_sid;
        self.send_sid += 1;
        let mut request = RequestBuffer::new(header, body, HeaderParam {
            url,
            h_sid: &0,
            hpack_encoder: None,
            q_sid: &0,
            qpack_encoder: None,
            body_len: 0,
            weight: &fingerprint.h2().weight,
            priority: &fingerprint.h2().priority,
        })?;
        loop {
            self.write_buffer.reset();
            let len = request.read(&mut self.write_buffer)?;
            if len == 0 { break; }
            self.stream.sync_write(self.write_buffer.filled())?;
        }
        Ok(sid)
    }

    pub fn recv(&mut self, responses: &mut HashMap<u64, Response>) -> HlsResult<Vec<u64>> {
        self.read_buffer.check_move(8192)?;
        self.stream.sync_read(&mut self.read_buffer)?;
        let response = responses.get_mut(&self.recv_sid).ok_or("resp not inited")?;
        let finish = response.extend_buffer(&mut self.read_buffer)?;
        if finish {
            let res = vec![self.recv_sid];
            self.recv_sid += 1;
            Ok(res)
        } else { Ok(vec![]) }
    }

    pub fn stream(&self) -> &Stream {
        &self.stream
    }
}