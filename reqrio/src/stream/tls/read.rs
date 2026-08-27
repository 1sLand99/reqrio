use crate::error::HlsResult;
use crate::*;
use std::io::Read;
#[cfg(feature = "aync")]
use std::pin::Pin;
#[cfg(feature = "aync")]
use std::task::{Context, Poll};
#[cfg(feature = "aync")]
use tokio::io::{AsyncRead, ReadBuf};

pub struct BufReading<'a, S> {
    pub(crate) buf: &'a mut Buffer,
    pub(crate) stream: &'a mut S,
    pub(crate) want_size: usize,
    #[cfg(feature = "aync")]
    pub(crate) timeout: &'a mut Timeout,
}

impl<'a, S: Read> BufReading<'a, S> {
    fn wait(self) -> HlsResult<usize> {
        debug_assert!(self.want_size > 0);
        self.buf.check_move(self.want_size).unwrap();
        while self.buf.len() < self.want_size {
            let len = self.stream.read(self.buf.unfilled())?;
            if len == 0 { return Err(HlsError::PeerClosedConnection); }
            self.buf.add_len(len);
        }
        Ok(self.buf.len())
    }
}


#[cfg(feature = "aync")]
impl<'a, S: AsyncRead + Unpin> Future for BufReading<'a, S> {
    type Output = HlsResult<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let reading = self.get_mut();
        debug_assert!(reading.want_size > 0);
        reading.buf.check_move(reading.want_size)?;
        while reading.buf.len() < reading.want_size {
            let stream = Pin::new(&mut reading.stream);
            let mut buf = ReadBuf::new(reading.buf.unfilled());
            match stream.poll_read(cx, &mut buf)? {
                Poll::Pending => {
                    reading.timeout.read_timeout()?;
                    return Poll::Pending;
                }
                Poll::Ready(_) => {
                    reading.timeout.reset_read();
                    let len = buf.filled().len();
                    if len == 0 { return Poll::Ready(Err(HlsError::PeerClosedConnection)); }
                    reading.buf.add_len(len);
                }
            }
        }
        Poll::Ready(Ok(reading.buf.len()))
    }
}


pub struct RecordReading<'a, S> {
    pub(crate) stream: &'a mut S,
    pub(crate) buf: &'a mut Buffer,
    #[cfg(feature = "aync")]
    pub(crate) timeout: &'a mut Timeout,
}

impl<'a, S: Read> RecordReading<'a, S> {
    pub fn wait(self) -> HlsResult<usize> {
        if self.buf.len() < 5 {
            BufReading {
                buf: self.buf,
                stream: self.stream,
                want_size: 5,
                #[cfg(feature = "aync")]
                timeout: self.timeout,
            }.wait()?;
        }
        let record_len = u16::from_be_bytes([self.buf.filled()[3], self.buf.filled()[4]]) as usize + 5;
        BufReading {
            buf: self.buf,
            stream: self.stream,
            want_size: record_len,
            #[cfg(feature = "aync")]
            timeout: self.timeout,
        }.wait()?;
        Ok(record_len)
    }
}

#[cfg(feature = "aync")]
impl<'a, S: AsyncRead + Unpin> Future for RecordReading<'a, S> {
    type Output = HlsResult<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let record_reading = self.get_mut();
        if record_reading.buf.len() < 5 {
            let mut reading = BufReading {
                stream: record_reading.stream,
                buf: record_reading.buf,
                want_size: 5,
                timeout: record_reading.timeout,
            };
            if Pin::new(&mut reading).poll(cx)?.is_pending() { return Poll::Pending; }
        }
        let filled = record_reading.buf.filled();
        let record_len = u16::from_be_bytes([filled[3], filled[4]]) as usize + 5;
        let mut reading = BufReading {
            stream: record_reading.stream,
            buf: record_reading.buf,
            want_size: record_len,
            timeout: record_reading.timeout,
        };
        if Pin::new(&mut reading).poll(cx)?.is_pending() { return Poll::Pending; }
        Poll::Ready(Ok(record_len))
    }
}