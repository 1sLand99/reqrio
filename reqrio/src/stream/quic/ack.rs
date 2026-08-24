use reqtls::quic::{AckRange, QUICConnection, QUICError, QUICFrame};
use reqtls::{Buf, Buffer, QUICFlag, QUICPacket, WriteExt};

pub(super) struct QUICAck<'a> {
    pub(super) flag: QUICFlag,
    pub(super) conn: &'a mut QUICConnection,
    pub(super) uw_buffer: &'a mut Buffer,
    pub(super) dcid: &'a Buf<'static>,
    pub(super) seq: &'a mut u64,
}


impl<'a> QUICAck<'a> {
    pub fn build(&mut self) -> Result<&[u8], QUICError> {
        self.conn.recv_nums_mut().sort();
        println!("{:?}", self.conn.recv_nums());
        let max_range = self.conn.recv_nums().max_range().ok_or(QUICError::MissingLargestNum)?;
        let mut ack_range = Vec::with_capacity(self.conn.recv_nums().count() - 1);
        let remain = self.conn.recv_nums().count() - 1;
        let mut pre_start = max_range.start;
        for i in 0..remain {
            let r = self.conn.recv_nums().get(remain - i - 1);
            ack_range.push(AckRange {
                gap: pre_start - r.end - 2,
                range: r.end - r.start,
            });
            pre_start = r.start;
        }
        let frame = QUICFrame::Ack {
            largest_acknowledged: max_range.end,
            ack_delay: 200,
            ack_range_count: ack_range.len(),
            first_ack_range: max_range.end - max_range.start,
            ack_range,
        };
        // println!("send_ack={:#?}", frame);
        let packet = QUICPacket::new_ack(self.flag, self.dcid.as_ref(), *self.seq, frame.len());
        let offset = self.uw_buffer.offset();
        let (_, filled) = self.conn.build_message(packet, vec![frame], self.uw_buffer)?;
        self.uw_buffer.reset_offset(offset);
        *self.seq += 1;
        Ok(filled)
    }
}