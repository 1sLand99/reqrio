mod error;
mod filed;

use crate::error::HlsResult;
use crate::form_data::filed::FormField;
use crate::reader::{ReadExt, Reader};
pub use error::FormError;
use reqrio_json::JsonValue;
use reqtls::WriteExt;
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::Path;
use std::sync::Arc;

pub enum FormRender {
    File(File),
    Bytes(Cursor<Vec<u8>>),
}

impl ReadExt for FormRender {
    fn read(&mut self, buf: &mut Reader) -> HlsResult<usize> {
        match self {
            FormRender::File(f) => {
                let len = f.read(buf.unfilled())?;
                buf.add_len(len);
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
            render: FormRender::File(file),
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
        if self.filetype != "" {
            len += 16 + self.filetype.len()
        }
        len
    }
}

pub(crate) struct FileFormBuffer<'a> {
    form: &'a mut FileForm,
    md5: Arc<String>,
    pos: usize,
}

impl<'a> ReadExt for FileFormBuffer<'a> {
    fn read(&mut self, buf: &mut Reader) -> HlsResult<usize> {
        let start = buf.offset().end;
        if self.pos == 0 {
            if buf.unfilled_len() < 34 { return Ok(buf.offset().end - start); }
            //line1
            buf.write_slice(b"--");
            buf.write_slice(self.md5.as_bytes());
            self.pos += 1;
        }
        if self.pos == 1 {
            let len = 56 + self.form.field_name.len() + self.form.filename.len();
            if buf.unfilled_len() < len { return Ok(buf.offset().end - start); }
            //line2
            buf.write_slice(b"\r\nContent-Disposition: form-data; name=\""); //40
            buf.write_slice(self.form.field_name.as_bytes());
            buf.write_slice(b"\"; filename=\""); //13
            buf.write_slice(self.form.filename.as_bytes());
            buf.write_slice(b"\"\r\n"); //3
            self.pos += 1;
        }
        if self.pos == 2 {
            if self.form.filetype != "" {
                let len = 16 + self.form.filetype.len();
                if buf.unfilled_len() < len { return Ok(buf.offset().end - start); }
                //line3
                buf.write_slice(b"Content-Type: "); //14
                buf.write_slice(self.form.filetype.as_bytes());
                buf.write_slice(b"\r\n");
            }
            self.pos += 1;
        }
        if self.pos == 3 {
            if buf.unfilled_len() < 2 { return Ok(buf.offset().end - start); }
            //line4
            buf.write_slice(b"\r\n");
            self.pos += 1;
        }
        if self.pos == 4 {
            //line5
            if buf.is_empty() { return Ok(buf.offset().end - start); }
            let len = self.form.render.read(buf)?;
            if len == 0 { self.pos += 1; }
        }
        if self.pos == 5 {
            if buf.unfilled_len()< 2 { return Ok(buf.offset().end - start); }
            //line6
            buf.write_slice(b"\r\n");
        }
        Ok(buf.offset().end - start)
    }
}


pub struct HttpFile {
    data: Vec<FormField>,
    forms: Vec<FileForm>,
}

impl HttpFile {
    pub fn new_bytes(bytes: impl Into<Vec<u8>>) -> HttpFile {
        HttpFile::new_bytes_data(JsonValue::Null, bytes)
    }

    pub fn new_bytes_data(data: JsonValue, bytes: impl Into<Vec<u8>>) -> HttpFile {
        HttpFile {
            data: data.into_entries().map(|(k, v)| FormField::new(k, v.dump())).collect(),
            forms: vec![FileForm::new_bytes(bytes)],
        }
    }

    pub fn new_path(path: impl AsRef<Path>) -> HlsResult<HttpFile> {
        HttpFile::new_path_data(JsonValue::Null, path)
    }

    pub fn new_path_data(data: JsonValue, path: impl AsRef<Path>) -> HlsResult<HttpFile> {
        Ok(HttpFile {
            data: data.into_entries().map(|(k, v)| FormField::new(k, v.dump())).collect(),
            forms: vec![FileForm::new_path(path)?],
        })
    }

    pub fn new_form(form: FileForm) -> HttpFile {
        HttpFile::new_form_data(JsonValue::Null, form)
    }

    pub fn new_form_data(data: JsonValue, form: FileForm) -> HttpFile {
        HttpFile {
            data: data.into_entries().map(|(k, v)| FormField::new(k, v.dump())).collect(),
            forms: vec![form],
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
        HttpFileBuffer {
            data: &self.data,
            len: self.len(),
            files: self.forms.iter_mut().map(|form| FileFormBuffer {
                form,
                md5: boundary.clone(),
                pos: 0,
            }).collect(),
            md5: boundary,
            row: 0,
            pos: 0,
        }
    }
}

pub struct HttpFileBuffer<'a> {
    data: &'a Vec<FormField>,
    files: Vec<FileFormBuffer<'a>>,
    md5: Arc<String>,
    len: usize,
    row: usize,
    pos: usize,
}

impl<'a> HttpFileBuffer<'a> {
    pub fn len(&self) -> usize { self.len }
}

impl<'a> ReadExt for HttpFileBuffer<'a> {
    fn read(&mut self, buf: &mut Reader) -> HlsResult<usize> {
        let start = buf.offset().end;
        if self.row == 0 {
            for (i, datum) in self.data.iter().enumerate() {
                if i < self.pos { continue; }
                let len = 85 + datum.name.len() + datum.value.len();
                if buf.unfilled_len() < len { return Ok(buf.offset().end - start); }
                //line1
                buf.write_slice(b"--");
                buf.write_slice(self.md5.as_bytes());
                buf.write_slice(b"--\r\n");
                //line2
                buf.write_slice(b"Content-Disposition: form-data; name=\""); //38
                buf.write_slice(datum.name.as_bytes());
                buf.write_slice(b"\"\r\n"); //3
                //line3
                buf.write_slice(b"\r\n");
                //line4
                buf.write_slice(datum.value.as_bytes());
                buf.write_slice(b"\r\n");
                //line5
                buf.write_slice(b"\r\n");
                self.pos += 1;
            }
            self.row += 1;
            self.pos = 0;
        }
        if self.row == 1 {
            for (i, form) in self.files.iter_mut().enumerate() {
                if i < self.pos { continue; }
                if buf.is_empty() { return Ok(buf.offset().end - start); }
                form.read(buf)?;
                if buf.is_empty() { return Ok(buf.offset().end - start); }
            }
            self.pos += 1;
        }
        if buf.unfilled_len() < 38 { return Ok(buf.offset().end - start); }
        buf.write_slice(b"--");
        buf.write_slice(self.md5.as_bytes());
        //此处待定
        buf.write_slice(b"--\r\n");

        Ok(buf.offset().end - start)
    }
}