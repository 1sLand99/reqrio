use crate::frame::Frame;
use crate::Reader;
use std::cmp::min;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::ops::Range;
use std::path::Path;
use std::process::Command;

struct FileHash {
    target: &'static str,
    dy_bcrypto: &'static str,
    dy_zap: &'static str,
    bcrypto: &'static str,
    zap: &'static str,
}

const FILE_HASHES: [FileHash; 4] = [
    FileHash {
        target: "x86_64-windows-msvc",
        dy_bcrypto: "608e212837ac670a9f0f271e244a2fd33cadd13dbfd9cf6a1580976b1dd239e2",
        dy_zap: "cf84db63855168850b7c47b9359b1825027cbb9442573a2355704986f6f6c971",
        bcrypto: "069e0e7babbe2645c231bab90e60db415a5f160e7c952b6fbdae20ed5e00deac",
        zap: "246deee2f83114b3efbd25431813e7bbf548bf1ea32cba98de0cada75356213e",
    },
    // FileHash {
    //     target: "windows-msvc-i686",
    //     bcrypto: "E82C70804F2989574BAD7E451BC622D1BFF9F16985F09FF86EECB48B7608D2A7",
    //     zap: "E82C70804F2989574BAD7E451BC622D1BFF9F16985F09FF86EECB48B7608D2A7",
    // },
    FileHash {
        target: "x86_64-windows-gnu",
        dy_bcrypto: "e0260087c2fcc2876b6a8f513ff1db54e6df4efa0232e5d8eb06feb3b4922ce6",
        dy_zap: "fcadb53c0434e084af1c3259fb69f706f467be170296b0c0444b19ffb681d0d0",
        bcrypto: "ed6a4585c55f380d4a49c36a85e9b6c55cd1c8cd0fa00fc8065dd40cbe9ffb1c",
        zap: "bd5642fbac1f1594b07b6e55f87999ee3e580891339222e9d30192411b083f39",
    },
    FileHash {
        target: "x86_64-linux-gnu",
        dy_bcrypto: "12a40be14347917b01d9f63585d1c97b8e59ae052e9aad4ba3f5d5140bed9a2b",
        dy_zap: "13749a584e89a6c754824eb517b0c396d01718d819c1fb6533874af2ee0ce602",
        bcrypto: "736123b1cb51e4c4172f57fd7ecfe248513ba0ece4c79e77b4969d4fb0c84eb7",
        zap: "3f333918a4eed17454b78192f182968e2ac30b8720b90878242865ddfa451e72",
    },
    // FileHash {
    //     target: "macos-x86_64",
    //     bcrypto: "E82C70804F2989574BAD7E451BC622D1BFF9F16985F09FF86EECB48B7608D2A7",
    //     zap: "E82C70804F2989574BAD7E451BC622D1BFF9F16985F09FF86EECB48B7608D2A7",
    // },
    FileHash {
        target: "aarch64-macos-",
        dy_bcrypto: "8770947a9fafa8b0493967603b41d1a8222da91bcc6dbce1b1f7bdc96a5c10ac",
        dy_zap: "58abf0ea7bf67576003ccd5858154bf2f6109aedfd99b5c9b3c8d56cb429c507",
        bcrypto: "a869839632798dc9c0e2035a4baaff66da45bdd3a5802ec2c7235e43eb6fdc30",
        zap: "7f314d6ed706d432d872b50389eb126276c387e547a5937a31927470176b998a",
    }
];

pub struct TkStream {
    stream: TcpStream,
    buffer: [u8; 4096],
    offset: Range<usize>,
}


impl TkStream {
    pub(crate) fn new(stream: TcpStream) -> TkStream {
        TkStream {
            stream,
            buffer: [0; 4096],
            offset: 0..0,
        }
    }

    fn read_size(&mut self, want: usize) -> Result<(), Box<dyn Error>> {
        let unfilled_size = self.buffer.len() - self.offset.end;
        if unfilled_size < want && self.offset.start != 0 {
            let filled = self.buffer[self.offset.clone()].to_vec();
            self.buffer[0..self.offset.len()].copy_from_slice(filled.as_slice());
            self.offset = 0..self.offset.len();
        }
        while self.offset.len() < want {
            let unfilled = &mut self.buffer[self.offset.end..];
            let len = self.stream.read(unfilled)?;
            if len == 0 && !unfilled.is_empty() { return Err("peer close".into()); }
            self.offset.end += len;
        }
        Ok(())
    }

    fn read_stream(&mut self) -> Result<usize, Box<dyn Error>> {
        if self.offset.len() < 4 { self.read_size(4)?; }
        let filled = &self.buffer[self.offset.clone()];
        let len = u32::from_be_bytes(filled[0..4].try_into()?) as usize + 4;
        self.read_size(len)?;
        Ok(len)
    }


    fn handle_stream(&mut self, tdr: &Path, target: &str) -> Result<(), Box<dyn Error>> {
        let len = self.read_stream()?;
        let off = self.offset.start..self.offset.start + len;
        let mut reader = Reader::from_slice(&self.buffer[off]);
        let frame_len = reader.read_u32()? as usize;
        let frame = Frame::from_reader(reader.read_reader(frame_len)?)?;
        match frame {
            Frame::Error { code, message } => return Err(format!("error: code={}; msg={}", code, message).into()),
            Frame::FileStream { filename, filesize } => {
                self.offset.start += reader.pos;
                let filesize = filesize as usize;
                let path = tdr.join("reqrio").join(filename);
                let dep_path = tdr.join("deps").join(filename);
                let t_path = tdr.join(filename);
                let filename = filename.to_string();
                let mut f = File::create(&path)?;
                let mut read_size = 0;
                if !self.offset.is_empty() {
                    let len = min(filesize, self.offset.len());
                    let off = self.offset.start..self.offset.start + len;
                    let filled = &self.buffer[off];
                    f.write_all(filled)?;
                    read_size += filled.len();
                    self.offset.start += filled.len();
                }
                loop {
                    if read_size >= filesize { break; }
                    let chunk_size = min(filesize - read_size, 4096);
                    let len = self.stream.read(&mut self.buffer[..chunk_size])?;
                    if len == 0 { return Err("invalid eof".into()); }
                    let filled = &self.buffer[..len];
                    f.write_all(filled)?;
                    read_size += filled.len();
                }
                f.flush()?;
                drop(f);
                if !self.file_cmp(path.as_path(), target, &filename)? { return Err("File Hash not correct".into()); }
                fs::copy(&path, dep_path)?;
                fs::copy(&path, t_path)?;
            }
            _ => unreachable!()
        };
        // self.offset.start += len;
        Ok(())
    }

    fn file_cmp(&self, path: &Path, target: &str, filename: &str) -> Result<bool, Box<dyn Error>> {
        let hash = FILE_HASHES.iter().find(|x| x.target == target);
        let Some(hash) = hash else { return Ok(false) };
        let dylib = !cfg!(feature = "static_link");
        if dylib && (filename == "bcrypto.lib" || filename == "zap.lib") { return Ok(true); }
        let file_hash = if cfg!(target_os = "windows") {
            let res = Command::new("powershell").args(["-NoProfile", "-Command"])
                .arg(format!("certutil -hashfile {} SHA256 | Select-Object -Index 1", path.display()))
                .output()?;
            if !res.stderr.is_empty() {
                panic!("{}", String::from_utf8_lossy(&res.stderr));
            }
            String::from_utf8(res.stdout)?
        } else if cfg!(target_os = "linux") {
            let res = Command::new("sha256sum").arg(path.display().to_string()).output()?;
            println!("{}", String::from_utf8_lossy(&res.stdout));
            println!("{}", String::from_utf8_lossy(&res.stderr));
            String::from_utf8(res.stdout)?.split(" ").next().unwrap_or("").to_string()
        } else {
            let res = Command::new("shasum").args(["-a", "256"])
                .arg(path.display().to_string()).output()?;
            println!("{}", String::from_utf8_lossy(&res.stdout));
            println!("{}", String::from_utf8_lossy(&res.stderr));
            String::from_utf8(res.stdout)?.split(" ").next().unwrap_or("").to_string()
        };
        println!("{:?} {:?} {:?}", hash.dy_bcrypto, hash.bcrypto, file_hash);
        match filename.split('.').next().unwrap_or("") {
            "bcrypto"|"libbcrypto" => Ok(if dylib { hash.dy_bcrypto } else { hash.bcrypto } == file_hash.trim()),
            "zap"|"libzap" => Ok(if dylib { hash.dy_zap } else { hash.zap } == file_hash.trim()),
            _ => Ok(false)
        }
    }

    pub fn fetch_lib(&mut self, frame: Frame, tdr: &Path, target: String) -> Result<(), Box<dyn Error>> {
        let mut buf = Vec::with_capacity(frame.len());
        frame.encode(&mut buf);
        self.stream.write_all(&buf)?;
        loop {
            if let Err(e) = self.handle_stream(tdr, &target) {
                if e.to_string().contains("peer close") { break; }
                return Err(e);
            }
        }
        Ok(())
    }
}