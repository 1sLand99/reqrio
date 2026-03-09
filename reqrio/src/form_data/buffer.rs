use crate::error::HlsResult;
use crate::form_data::FormRender;
use crate::reader::{ReadExt, Reader, RefReader};
use reqtls::WriteExt;

pub struct HttpFileBuffer<'a> {
    pub(crate) data_readers: Vec<RefReader<&'a [u8]>>,
    pub(crate) files: Vec<FileFormBuffer<'a>>,
    pub(crate) suffix_reader: RefReader<&'a [u8]>,
    pub(crate) len: usize,
    pub(crate) row: usize,
    pub(crate) pos: usize,
    pub(crate) wrote: bool,
}

impl<'a> HttpFileBuffer<'a> {
    pub fn len(&self) -> usize { self.len }
}


impl<'a> ReadExt for HttpFileBuffer<'a> {
    fn wrote(&self) -> bool {
        self.wrote
    }

    fn read(&mut self, buf: &mut Reader) -> HlsResult<usize> {
        let start = buf.offset().end;
        if self.row == 0 {
            for (index, data_reader) in self.data_readers.iter_mut().enumerate() {
                if index < self.pos { continue; }
                data_reader.read(buf)?;
                match data_reader.wrote() {
                    true => self.pos += 1,
                    false => return Ok(buf.offset().end - start)
                }
            }
            self.row += 1;
            self.pos = 0;
        }
        if self.row == 1 {
            for (i, form) in self.files.iter_mut().enumerate() {
                if i < self.pos { continue; }
                form.read(buf)?;
                match form.wrote() {
                    true => self.pos += 1,
                    false => return Ok(buf.offset().end - start)
                }
            }
            self.row += 1;
        }
        if self.row == 2 {
            self.suffix_reader.read(buf)?;
            match self.suffix_reader.wrote() {
                true => self.pos += 1,
                false => return Ok(buf.offset().end - start)
            }
        }
        Ok(buf.offset().end - start)
    }
}

pub(crate) struct FileFormBuffer<'a> {
    pub(crate) prefix_reader: RefReader<&'a [u8]>,
    pub(crate) file_reader: &'a mut FormRender,
    pub(crate) suffix_reader: RefReader<&'a [u8]>,
    pub(crate) pos: usize,
    pub(crate) wrote: bool,
}

impl<'a> ReadExt for FileFormBuffer<'a> {
    fn wrote(&self) -> bool {
        self.wrote
    }

    fn read(&mut self, buf: &mut Reader) -> HlsResult<usize> {
        let start = buf.offset().end;
        if self.pos == 0 {
            self.prefix_reader.read(buf)?;
            match self.prefix_reader.wrote() {
                true => self.pos += 1,
                false => return Ok(buf.offset().end - start),
            }
        }
        if self.pos == 1 {
            self.file_reader.read(buf)?;
            match self.file_reader.wrote() {
                true => self.pos += 1,
                false => return Ok(buf.offset().end - start),
            }
        }

        if self.pos == 2 {
            self.suffix_reader.read(buf)?;
            match self.suffix_reader.wrote() {
                true => self.pos += 1,
                false => return Ok(buf.offset().end - start),
            }
        }
        self.wrote = true;
        Ok(buf.offset().end - start)
    }
}