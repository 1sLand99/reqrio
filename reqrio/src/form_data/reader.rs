use std::fs::File;
use std::io::{Cursor, Read};
use crate::error::HlsResult;
use crate::reader::{ReadExt, Reader, RefReader};
use reqtls::WriteExt;

pub struct HttpFileReader<'a> {
    pub(crate) data_readers: Vec<RefReader<&'a [u8]>>,
    pub(crate) files: Vec<FileFormReader<'a>>,
    pub(crate) suffix_reader: RefReader<&'a [u8]>,
    pub(crate) row: usize,
    pub(crate) pos: usize,
    pub(crate) wrote: bool,
}


impl<'a> ReadExt for HttpFileReader<'a> {
    fn wrote(&self) -> bool {
        self.wrote
    }

    fn len(&self) -> usize {
        let data_len: usize = self.data_readers.iter().map(|x| x.len()).sum();
        let file_len: usize = self.files.iter().map(|x| x.len()).sum();
        let suffix_len: usize = self.suffix_reader.len();
        data_len + file_len + suffix_len
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
        self.wrote = true;
        Ok(buf.offset().end - start)
    }
}

pub enum MultiRender<'a> {
    File((usize, usize, File)),
    Bytes(Cursor<&'a [u8]>),
}

impl<'a> ReadExt for MultiRender<'a> {
    fn wrote(&self) -> bool {
        match self {
            MultiRender::File((wrote, size, _)) => wrote == size,
            MultiRender::Bytes(bytes) => bytes.position() as usize == bytes.get_ref().len(),
        }
    }

    fn len(&self) -> usize {
        match self {
            MultiRender::File((_, size, _)) => *size,
            MultiRender::Bytes(bs) => bs.get_ref().len()
        }
    }

    fn read(&mut self, buf: &mut Reader) -> HlsResult<usize> {
        match self {
            MultiRender::File((wrote, _, f)) => {
                let len = f.read(buf.unfilled())?;
                buf.add_len(len);
                *wrote += len;
                Ok(len)
            }
            MultiRender::Bytes(bs) => {
                let len = bs.read(buf.unfilled())?;
                buf.add_len(len);
                Ok(len)
            }
        }
    }
}

pub(crate) struct FileFormReader<'a> {
    pub(crate) prefix_reader: RefReader<&'a [u8]>,
    pub(crate) file_reader: MultiRender<'a>,
    pub(crate) suffix_reader: RefReader<&'a [u8]>,
    pub(crate) pos: usize,
    pub(crate) wrote: bool,
}

impl<'a> ReadExt for FileFormReader<'a> {
    fn wrote(&self) -> bool {
        self.wrote
    }

    fn len(&self) -> usize {
        self.prefix_reader.len() + self.file_reader.len() + self.suffix_reader.len()
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
                false => return Ok(buf.offset().end - start)
            }
        }
        self.wrote = true;
        Ok(buf.offset().end - start)
    }
}