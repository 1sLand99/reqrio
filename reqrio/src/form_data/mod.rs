mod error;
mod field;
mod reader;

use crate::error::HlsResult;
use crate::form_data::field::FormField;
use crate::form_data::reader::MultiRender;
use crate::reader::RefReader;
pub use error::FormError;
use reader::FileFormReader;
pub use reader::HttpFileReader;
use reqrio_json::JsonValue;
use std::fs::File;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::Arc;

enum InputType {
    Bytes(Vec<u8>),
    Path(PathBuf),
}

impl InputType {
    fn as_reader(&self) -> HlsResult<MultiRender<'_>> {
        match self {
            InputType::Bytes(bytes) => Ok(MultiRender::Bytes(Cursor::new(bytes))),
            InputType::Path(path) => {
                let filesize = path.metadata()?.len() as usize;
                let file = File::open(path)?;
                Ok(MultiRender::File((0, filesize, file)))
            }
        }
    }
}

pub struct FileForm {
    filename: String,
    filetype: String,
    field_name: String,
    input: InputType,
}

impl Default for FileForm {
    fn default() -> Self {
        FileForm {
            filename: "123.txt".to_string(),
            filetype: "".to_string(),
            field_name: "file".to_string(),
            input: InputType::Bytes(vec![]),
        }
    }
}

impl FileForm {
    pub fn new_path(path: impl AsRef<Path>) -> HlsResult<FileForm> {
        let path = path.as_ref().to_path_buf();
        let filename = path.file_name().ok_or(FormError::GetFilenameError)?.display().to_string();
        Ok(FileForm {
            filename,
            field_name: "file".to_string(),
            input: InputType::Path(path),
            ..Default::default()
        })
    }

    pub fn new_bytes(bytes: impl Into<Vec<u8>>) -> FileForm {
        FileForm {
            filename: "1223.txt".to_string(),
            field_name: "file".to_string(),
            input: InputType::Bytes(bytes.into()),
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
        let mut len = 94 + self.field_name.len() + self.filename.len() + self.filesize().unwrap_or(0);
        if !self.filetype.is_empty() {
            len += 16 + self.filetype.len()
        }
        len
    }

    pub fn filesize(&self) -> HlsResult<usize> {
        match &self.input {
            InputType::Bytes(bs) => Ok(bs.len()),
            InputType::Path(f) => Ok(f.metadata()?.len() as usize),
        }
    }

    pub fn filename(&self) -> &str { &self.filename }

    pub(crate) fn as_form_render<'a>(&'a self, boundary: &'a Arc<String>) -> HlsResult<FileFormReader<'a>> {
        let mut reader: RefReader<&[u8]> = RefReader::default();
        //line1
        reader.add_buf(b"--");
        reader.add_buf(boundary.as_bytes());
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
        Ok(FileFormReader {
            prefix_reader: reader,
            //line5
            file_reader: self.input.as_reader()?,
            //line6
            suffix_reader: RefReader::new_buf(b"\r\n"),
            pos: 0,
            wrote: false,
        })
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

    pub fn forms(&self) -> &[FileForm] {
        &self.forms
    }

    pub(crate) fn as_reader(&self) -> HlsResult<HttpFileReader<'_>> {
        let mut suffix_reader: RefReader<&[u8]> = RefReader::default();
        suffix_reader.add_buf(b"--");
        suffix_reader.add_buf(self.boundary.as_bytes());
        //此处待定
        suffix_reader.add_buf(b"--");
        let mut files = vec![];
        for form in &self.forms {
            files.push(form.as_form_render(&self.boundary)?);
        }
        Ok(HttpFileReader {
            data_readers: self.data.iter().map(|x| x.as_render(&self.boundary)).collect(),
            files,
            suffix_reader,
            row: 0,
            pos: 0,
            wrote: false,
        })
    }
}

