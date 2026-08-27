use crate::error::HlsResult;
use crate::*;
use std::io::Write;
#[cfg(feature = "aync")]
use std::pin::Pin;
#[cfg(feature = "aync")]
use std::task::{Context, Poll};
#[cfg(feature = "aync")]
use tokio::io::AsyncWrite;


pub struct BufWriting<'a, S> {
    pub(crate) stream: &'a mut S,
    pub(crate) buf: &'a mut Buffer,
    #[cfg(feature = "aync")]
    pub(crate) timeout: &'a mut Timeout,
}

impl<'a, S: Write> BufWriting<'a, S> {
    pub(crate) fn wait(self) -> HlsResult<()> {
        while !self.buf.is_empty() {
            let len = self.stream.write(self.buf.filled())?;
            self.buf.used_empty(len);
        }
        Ok(())
    }
}
#[cfg(feature = "aync")]
impl<'a, S: AsyncWrite + Unpin> Future for BufWriting<'a, S> {
    type Output = HlsResult<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let writer = self.get_mut();
        loop {
            let stream = Pin::new(&mut writer.stream);
            match stream.poll_write(cx, writer.buf.filled())? {
                Poll::Ready(wrote) => {
                    writer.timeout.reset_write();
                    if wrote == 0 { return Poll::Ready(Err(HlsError::PeerClosedConnection)); }
                    if writer.buf.used_empty(wrote) { break; }
                }
                Poll::Pending => {
                    writer.timeout.write_timeout()?;
                    return Poll::Pending;
                }
            }
        }
        writer.buf.reset();
        Poll::Ready(Ok(()))
    }
}
