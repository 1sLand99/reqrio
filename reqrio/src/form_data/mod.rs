mod error;
mod filed;

use crate::error::HlsResult;
use crate::form_data::filed::FormField;
use crate::reader::{ReadExt, Reader, RefReader};
pub use error::FormError;
use reqrio_json::JsonValue;
use reqtls::WriteExt;
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::Path;
use std::sync::Arc;

pub enum FormRender {
    File((bool, File)),
    Bytes(Cursor<Vec<u8>>),
}

impl ReadExt for FormRender {
    fn wrote(&self) -> bool {
        match self {
            FormRender::File((wrote, _)) => *wrote,
            FormRender::Bytes(bytes) => bytes.position() as usize == bytes.get_ref().len(),
        }
    }

    fn read(&mut self, buf: &mut Reader) -> HlsResult<usize> {
        match self {
            FormRender::File((wrote, f)) => {
                let len = f.read(buf.unfilled())?;
                buf.add_len(len);
                *wrote = len == 0;
                Ok(len)
            }
            FormRender::Bytes(bs) => {
                let len = bs.read(buf.unfilled())?;
                buf.add_len(len);
                Ok(len)
            }
        }
    }
}

pub struct FileForm {
    filename: String,
    filetype: String,
    filesize: usize,
    field_name: String,
    boundary: Arc<String>,
    render: FormRender,
}
impl FileForm {
    pub fn new_path(path: impl AsRef<Path>) -> HlsResult<FileForm> {
        let path = path.as_ref();
        let filename = path.file_name().ok_or(FormError::GetFilenameError)?.display().to_string();
        let file = File::open(path)?;
        let metadata = file.metadata()?;
        let filesize = metadata.len() as usize;
        Ok(FileForm {
            filename,
            filetype: "".to_string(),
            filesize,
            field_name: "".to_string(),
            boundary: Arc::new("".to_string()),
            render: FormRender::File((false, file)),
        })
    }

    pub fn new_bytes(bytes: impl Into<Vec<u8>>) -> FileForm {
        let bytes = bytes.into();
        let filesize = bytes.len();
        FileForm {
            filename: "1223.txt".to_string(),
            filetype: "".to_string(),
            filesize,
            field_name: "".to_string(),
            boundary: Arc::new("".to_string()),
            render: FormRender::Bytes(Cursor::new(bytes)),
        }
    }

    pub fn with_filename(mut self, filename: impl ToString) -> Self {
        self.set_filename(filename);
        self
    }

    pub fn with_filetype(mut self, filetype: impl ToString) -> Self {
        self.set_filetype(filetype);
        self
    }

    pub fn with_field_name(mut self, field_name: impl ToString) -> Self {
        self.set_field_name(field_name);
        self
    }

    pub fn set_filename(&mut self, filename: impl ToString) {
        self.filename = filename.to_string()
    }

    pub fn set_filetype(&mut self, filetype: impl ToString) {
        self.filetype = filetype.to_string()
    }

    pub fn set_field_name(&mut self, field: impl ToString) {
        self.field_name = field.to_string()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn len(&self) -> usize {
        let mut len = 94 + self.field_name.len() + self.filename.len() + self.filesize;
        if !self.filetype.is_empty() {
            len += 16 + self.filetype.len()
        }
        len
    }

    pub(crate) fn as_form_buffer(&mut self, boundary: &Arc<String>) -> FileFormBuffer<'_> {
        self.boundary = boundary.clone();
        let mut reader: RefReader<&[u8]> = RefReader::default();
        //line1
        reader.add_buf(b"--");
        reader.add_buf(self.boundary.as_bytes());
        //line2
        reader.add_buf(b"\r\nContent-Disposition: form-data; name=\"");
        reader.add_buf(self.field_name.as_bytes());
        reader.add_buf(b"\"; filename=\"");
        reader.add_buf(self.filename.as_bytes());
        reader.add_buf(b"\"\r\n");
        //line3
        if !self.filetype.is_empty() {
            //line3
            reader.add_buf(b"Content-Type: "); //14
            reader.add_buf(self.filetype.as_bytes());
            reader.add_buf(b"\r\n");
        }
        //line4
        reader.add_buf(b"\r\n");
        FileFormBuffer {
            prefix_reader: reader,
            //line5
            file_reader: &mut self.render,
            //line6
            suffix_reader: RefReader::new_buf(b"\r\n"),
            pos: 0,
            wrote: false,
        }
    }
}

pub(crate) struct FileFormBuffer<'a> {
    prefix_reader: RefReader<&'a [u8]>,
    file_reader: &'a mut FormRender,
    suffix_reader: RefReader<&'a [u8]>,
    pos: usize,
    wrote: bool,
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
        Ok(buf.offset().end - start)
    }
}


pub struct HttpFile {
    data: Vec<FormField>,
    forms: Vec<FileForm>,
    boundary: Arc<String>,
}

impl HttpFile {
    pub fn new_bytes(bytes: impl Into<Vec<u8>>) -> HttpFile {
        HttpFile::new_bytes_data(JsonValue::Null, bytes)
    }

    pub fn new_bytes_data(data: JsonValue, bytes: impl Into<Vec<u8>>) -> HttpFile {
        HttpFile {
            data: data.into_entries().map(|(k, v)| FormField::new(k, v.dump())).collect(),
            forms: vec![FileForm::new_bytes(bytes)],
            boundary: Arc::new("".to_string()),
        }
    }

    pub fn new_path(path: impl AsRef<Path>) -> HlsResult<HttpFile> {
        HttpFile::new_path_data(JsonValue::Null, path)
    }

    pub fn new_path_data(data: JsonValue, path: impl AsRef<Path>) -> HlsResult<HttpFile> {
        Ok(HttpFile {
            data: data.into_entries().map(|(k, v)| FormField::new(k, v.dump())).collect(),
            forms: vec![FileForm::new_path(path)?],
            boundary: Arc::new("".to_string()),
        })
    }

    pub fn new_form(form: FileForm) -> HttpFile {
        HttpFile::new_form_data(JsonValue::Null, form)
    }

    pub fn new_form_data(data: JsonValue, form: FileForm) -> HttpFile {
        HttpFile {
            data: data.into_entries().map(|(k, v)| FormField::new(k, v.dump())).collect(),
            forms: vec![form],
            boundary: Arc::new("".to_string()),
        }
    }

    pub fn add_form(&mut self, form: FileForm) {
        self.forms.push(form);
    }

    pub fn remove_form(&mut self, index: usize) -> FileForm {
        self.forms.remove(index)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn len(&self) -> usize {
        let filed_size: usize = self.data.iter().map(|x| 85 + x.name.len() + x.value.len()).sum();
        let form_size: usize = self.forms.iter().map(|x| x.len()).sum();
        filed_size + form_size + 38
    }

    pub(crate) fn as_buffer(&mut self, boundary: Arc<String>) -> HttpFileBuffer<'_> {
        self.boundary = boundary;
        let mut suffix_reader: RefReader<&[u8]> = RefReader::default();
        suffix_reader.add_buf(b"--");
        suffix_reader.add_buf(self.boundary.as_bytes());
        //此处待定
        suffix_reader.add_buf(b"--\r\n");
        HttpFileBuffer {
            len: self.len(),
            data_readers: self.data.iter_mut().map(|x| x.as_file_render(&self.boundary)).collect(),
            files: self.forms.iter_mut().map(|form| form.as_form_buffer(&self.boundary)).collect(),
            suffix_reader,
            row: 0,
            pos: 0,
            wrote: false,
        }
    }
}

pub struct HttpFileBuffer<'a> {
    data_readers: Vec<RefReader<&'a [u8]>>,
    files: Vec<FileFormBuffer<'a>>,
    suffix_reader: RefReader<&'a [u8]>,
    len: usize,
    row: usize,
    pos: usize,
    wrote: bool,
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
            self.pos += 1;
        }
        if self.pos == 2 {
            self.suffix_reader.read(buf)?;
            match self.suffix_reader.wrote() {
                true => self.pos += 1,
                false => return Ok(buf.offset().end - start)
            }
        }
        Ok(buf.offset().end - start)
    }
}