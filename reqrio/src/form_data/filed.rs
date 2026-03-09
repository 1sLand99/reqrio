use crate::reader::RefReader;
use std::sync::Arc;

pub(crate) struct FormField {
    pub(crate) name: String,
    pub(crate) value: String,
    pub(crate) boundary: Arc<String>,
}

impl FormField {
    pub fn new(name: impl ToString, value: impl ToString) -> Self {
        FormField {
            name: name.to_string(),
            value: value.to_string(),
            boundary: Arc::new(String::new()),
        }
    }

    pub fn as_file_render(&mut self, md5: &Arc<String>) -> RefReader<&[u8]> {
        self.boundary = md5.clone();
        //line1
        let mut reader: RefReader<&[u8]> = RefReader::default();
        reader.add_buf(b"--");
        reader.add_buf(self.boundary.as_bytes());
        reader.add_buf(b"--\r\n");
        //line2
        reader.add_buf(b"Content-Disposition: form-data; name=\"");
        reader.add_buf(self.name.as_bytes());
        reader.add_buf(b"\"\r\n");
        //line3
        reader.add_buf(b"\r\n");
        //line4
        reader.add_buf(self.value.as_bytes());
        reader.add_buf(b"\r\n");
        //line5
        reader.add_buf(b"\r\n");
        reader
    }
}