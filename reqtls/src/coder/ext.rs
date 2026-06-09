pub trait StreamDecode<E> {
    fn decompress(&mut self, data: &[u8], out: &mut [u8]) -> Result<usize, E>;
}

pub trait StreamEncode<E> {
    fn compress(&mut self, data: &[u8], out: &mut [u8]) -> Result<usize, E>;
    fn flush(&mut self, out: &mut [u8])->Result<usize, E>;
}