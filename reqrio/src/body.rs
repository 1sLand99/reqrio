use crate::error::HlsResult;
use crate::form_data::{HttpFile, HttpFileBuffer};
use crate::reader::ReadExt;
use crate::Buffer;
use std::io::{Cursor, Read};
use std::sync::Arc;

pub(crate) enum BodyType {
    Bytes(Cursor<Vec<u8>>),
    Files(HttpFile),
}

impl BodyType {
    pub fn new_byte(bytes: Vec<u8>) -> Self {
        BodyType::Bytes(Cursor::new(bytes))
    }

    // pub fn is_empty(&self) -> bool {
    //     match self {
    //         BodyType::Bytes(b) => b.is_empty(),
    //         BodyType::Files { files, .. } => files.is_empty()
    //     }
    // }
    pub fn len(&self) -> usize {
        match self {
            BodyType::Bytes(b) => b.get_ref().len(),
            BodyType::Files(f) => f.len()
        }
    }

    // pub fn write_to<W: WriteExt>(&self, writer: &mut W, md5: &str) {
    //     match self {
    //         BodyType::Bytes(bs) => writer.write_slice(bs.as_slice()),
    //         BodyType::Files { data, files } => {
    //             for datum in data {
    //                 //line1
    //                 writer.write_slice(b"--");
    //                 writer.write_slice(md5.as_bytes());
    //                 writer.write_slice(b"--\r\n");
    //                 //line2
    //                 writer.write_slice(b"Content-Disposition: form-data; name=\""); //38
    //                 writer.write_slice(datum.name.as_bytes());
    //                 writer.write_slice(b"\"\r\n"); //3
    //                 //line3
    //                 writer.write_slice(b"\r\n");
    //                 //line4
    //                 writer.write_slice(datum.value.as_bytes());
    //                 writer.write_slice(b"\r\n");
    //                 //line5
    //                 writer.write_slice(b"\r\n");
    //             }
    //             for form_data in files {
    //                 //line1
    //                 writer.write_slice(b"--");
    //                 writer.write_slice(md5.as_bytes());
    //                 writer.write_slice(b"\r\nContent-Disposition: form-data; name=\""); //40
    //                 writer.write_slice(form_data.filed_name().as_bytes());
    //                 writer.write_slice(b"\"; filename=\""); //13
    //                 writer.write_slice(form_data.filename().as_bytes());
    //                 writer.write_slice(b"\"\r\n"); //3
    //                 if form_data.file_type() != "" {
    //                     writer.write_slice(b"Content-Type: ");
    //                     writer.write_slice(form_data.file_type().as_bytes());
    //                     writer.write_slice(b"\r\n");
    //                 }
    //                 writer.write_slice(b"\r\n");
    //                 writer.write_slice(form_data.raw_bytes());
    //                 writer.write_slice(b"\r\n");
    //             }
    //             writer.write_slice(b"--");
    //             writer.write_slice(md5.as_bytes());
    //             //此处待定
    //             writer.write_slice(b"--\r\n");
    //         }
    //     }
    // }

    // pub fn to_bytes(&self) -> &[u8] {
    //     match self {
    //         BodyType::Bytes(b) => b.as_slice(),
    //         BodyType::Files { .. } => panic!("unsupported body type"),
    //     }
    // }

    pub fn as_buffer<'a>(&'a mut self, boundary: &Arc<String>) -> BodyTypeBuffer<'a> {
        match self {
            BodyType::Bytes(bs) => BodyTypeBuffer::Bytes(bs),
            BodyType::Files(hfs) => BodyTypeBuffer::Files(hfs.as_buffer(boundary.clone()))
        }
    }
}


pub(crate) enum BodyTypeBuffer<'a> {
    Bytes(&'a mut Cursor<Vec<u8>>),
    Files(HttpFileBuffer<'a>),
}

impl<'a> ReadExt for BodyTypeBuffer<'a> {
    fn read(&mut self, buf: &mut Buffer) -> HlsResult<usize> {
        match self {
            BodyTypeBuffer::Bytes(bs) => {
                let len = bs.read(buf.unfilled_mut())?;
                buf.add_len(len);
                Ok(len)
            }
            BodyTypeBuffer::Files(hfs) => hfs.read(buf),
        }
    }
}