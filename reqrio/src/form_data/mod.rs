mod error;
mod filed;
mod buffer;

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
pub use buffer::HttpFileBuffer;
use buffer::FileFormBuffer;

pub enum FormRender {
    File((usize, usize, File)),
    Bytes(Cursor<Vec<u8>>),
}

impl ReadExt for FormRender {
    fn wrote(&self) -> bool {
        match self {
            FormRender::File((wrote, size, _)) => wrote == size,
            FormRender::Bytes(bytes) => bytes.position() as usize == bytes.get_ref().len(),
        }
    }

    fn read(&mut self, buf: &mut Reader) -> HlsResult<usize> {
        match self {
            FormRender::File((wrote, _, f)) => {
                let len = f.read(buf.unfilled())?;
                buf.add_len(len);
                *wrote += len;
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

impl Default for FileForm {
    fn default() -> Self {
        FileForm {
            filename: "123.txt".to_string(),
            filetype: "".to_string(),
            filesize: 0,
            field_name: "file".to_string(),
            boundary: Arc::new("".to_string()),
            render: FormRender::Bytes(Cursor::new(vec![])),
        }
    }
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
            filesize,
            field_name: "file".to_string(),
            render: FormRender::File((0, filesize, file)),
            ..Default::default()
        })
    }

    pub fn new_bytes(bytes: impl Into<Vec<u8>>) -> FileForm {
        let bytes = bytes.into();
        let filesize = bytes.len();
        FileForm {
            filename: "1223.txt".to_string(),
            filesize,
            field_name: "file".to_string(),
            render: FormRender::Bytes(Cursor::new(bytes)),
            ..Default::default()
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



pub struct HttpFile {
    data: Vec<FormField>,
    forms: Vec<FileForm>,
    boundary: Arc<String>,
}

impl Default for HttpFile {
    fn default() -> Self {
        HttpFile {
            data: vec![],
            forms: vec![],
            boundary: Arc::new(String::new()),
        }
    }
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

    pub fn with_boundary(mut self, boundary: Arc<String>) -> HttpFile {
        self.set_boundary(boundary);
        self
    }

    pub fn set_boundary(&mut self, boundary: Arc<String>) {
        self.boundary = boundary;
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

    pub(crate) fn as_buffer(&mut self) -> HttpFileBuffer<'_> {
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

