use crate::file::HttpFile;
use crate::Buffer;
use crate::error::HlsResult;
use crate::reader::{BufReader, ReadExt};

pub(crate) struct HttpField {
    pub(crate) name: String,
    pub(crate) value: String,
}

pub(crate) enum BodyType {
    Bytes(BufReader<Vec<u8>>),
    Files { data: Vec<HttpField>, files: Vec<HttpFile> },
}

impl BodyType {
    pub fn new_byte(bytes: Vec<u8>) -> Self {
        BodyType::Bytes(BufReader::new(bytes))
    }

    // pub fn is_empty(&self) -> bool {
    //     match self {
    //         BodyType::Bytes(b) => b.is_empty(),
    //         BodyType::Files { files, .. } => files.is_empty()
    //     }
    // }
    pub fn len(&self) -> usize {
        match self {
            BodyType::Bytes(b) => b.len(),
            BodyType::Files { data, files } => {
                let mut len = 0;
                for datum in data {
                    len += 2 + 32 + 2 + 2;
                    len += 39 + datum.name.len() + 2;
                    len += 2;
                    len += datum.value.len() + 2;
                    len += 2
                }
                for file in files {
                    len += 58 + 32 + file.filed_name().len() + file.filename().len();
                    if file.file_type() != "" {
                        len += 16 + file.file_type().len();
                    }
                    len += 2;
                    len += file.filesize();
                    len += 2;
                }
                len += 6 + 32;
                len
            }
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
    //             for file in files {
    //                 //line1
    //                 writer.write_slice(b"--");
    //                 writer.write_slice(md5.as_bytes());
    //                 writer.write_slice(b"\r\nContent-Disposition: form-data; name=\""); //40
    //                 writer.write_slice(file.filed_name().as_bytes());
    //                 writer.write_slice(b"\"; filename=\""); //13
    //                 writer.write_slice(file.filename().as_bytes());
    //                 writer.write_slice(b"\"\r\n"); //3
    //                 if file.file_type() != "" {
    //                     writer.write_slice(b"Content-Type: ");
    //                     writer.write_slice(file.file_type().as_bytes());
    //                     writer.write_slice(b"\r\n");
    //                 }
    //                 writer.write_slice(b"\r\n");
    //                 writer.write_slice(file.raw_bytes());
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
}


impl ReadExt for BodyType {
    fn read(&mut self, buf: &mut Buffer) -> HlsResult<usize> {
        match self {
            BodyType::Bytes(bs) => bs.read(buf),
            BodyType::Files { .. } => Err("unsupported body type".into()),
        }
    }
}

