use crate::reader::RefReader;
use std::sync::Arc;

pub(crate) struct FormField {
    pub(crate) name: String,
    pub(crate) value: String,
}

impl FormField {
    pub fn new(name: impl ToString, value: impl ToString) -> Self {
        FormField {
            name: name.to_string(),
            value: value.to_string(),
        }
    }

    pub fn as_file_render<'a>(&'a self, md5: &'a Arc<String>) -> RefReader<&'a [u8]> {
        //line1
        let mut reader: RefReader<&[u8]> = RefReader::default();
        reader.add_buf(b"--");
        reader.add_buf(md5.as_bytes());
        reader.add_buf(b"--\r\n");
        //line2
        reader.add_buf(b"Content-Disposition: form-data; name=\"");
        reader.add_buf(self.name.as_bytes());
        reader.add_buf(b"\"\r\n");
        //line3
        reader.add_buf(b"\r\n");
        //line4
        reader.add_buf(self.value.as_bytes());
        // reader.add_buf(b"\r\n");
        //line5
        reader.add_buf(b"\r\n");
        reader
    }
}