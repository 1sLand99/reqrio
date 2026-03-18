use crate::error::HlsResult;
use crate::hpack::huffman::decode::table::DecodeNode;

pub(crate) struct DecodeReader {
    id: usize,
    buf: usize,
    buf_size: usize,
    tail: usize,
    tail_size: usize,
}

impl DecodeReader {
    pub fn new() -> Self {
        Self {
            id: 0,
            buf: 0,
            buf_size: 0,
            tail: 0,
            tail_size: 0,
        }
    }
    pub fn decode(&mut self, byte: u8, dst: &mut Vec<u8>) -> HlsResult<()> {
        self.buf <<= 8; // make space for new chunk
        self.buf_size += 8;
        self.buf |= byte as usize; // apply new chunk

        loop {
            if self.buf_size < 5 { // has chunks to process
                break;
            } else {
                self.decode_next(dst)?;
            }
        }

        Ok(())
    }

    pub fn finalize(&mut self, dst: &mut Vec<u8>) -> HlsResult<()> {
        let shift_len = (self.buf_size as f64 / 5.0).ceil() as usize * 5 - self.buf_size; // how much missing to chunk size

        self.buf <<= shift_len; // expand buffer to chunk size
        self.buf_size += shift_len;

        if self.buf_size >= 5 { // has chunks to process
            if let Some(node) = Self::find_target(self.id, self.buf) && shift_len <= node.leftover as usize { // has another character
                self.decode_next(dst)?;
            }
        }

        self.buf >>= shift_len; // remove leftover
        self.buf_size -= shift_len;

        self.tail <<= self.buf_size; // append buffer to tail
        self.tail_size += self.buf_size;
        self.tail |= self.buf;
        self.buf = 0;
        self.buf_size = 0;

        if ![0, 1, 3, 7, 15, 31, 63, 127].contains(&self.tail) { // validate padding
            return Err("Check huffman tail fail".into());
        }

        self.tail = 0; // reset (make object reusable)
        self.tail_size = 0;

        Ok(())
    }

    fn decode_next(&mut self, dst: &mut Vec<u8>) -> HlsResult<()> {
        let key = self.buf >> (self.buf_size - 5);
        let node = Self::find_target(self.id, key).ok_or(format!("get huffman node error,key: {}", self.id))?;

        self.buf -= key >> node.leftover << (self.buf_size - 5 + node.leftover as usize); // remove key from buffer
        self.buf_size -= 5 - node.leftover as usize;

        self.tail <<= 5 - node.leftover as usize; // append chunk to tail
        self.tail |= key >> node.leftover;
        self.tail_size += 5 - node.leftover as usize;

        if let Some(ascii) = node.ascii {
            self.id = 0;
            self.tail = 0;
            self.tail_size = 0;
            if ascii < 256 { // valid character
                dst.push(ascii as u8);
                Ok(())
            } else {
                Err("Invalid huffman table ascii".into())
            }
        } else if let Some(next_id) = node.next { // transition
            self.id = next_id as usize;
            Ok(())
        } else {
            Err("decode huffman error".into())
        }
    }

    fn find_target(id: usize, key: usize) -> Option<&'static DecodeNode> {
        let transitions = super::table::DECODE_TABLE.get(id)?;
        transitions.get(key)
    }
}
