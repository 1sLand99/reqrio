use super::super::version::Version;
use crate::{BufferError, WriteExt};

#[derive(Debug)]
pub struct SupportVersions {
    len: u8,
    versions: Vec<Version>,
}

impl SupportVersions {
    pub fn new() -> Self {
        SupportVersions {
            len: 0,
            versions: vec![],
        }
    }

    pub fn from_bytes(bytes: &[u8], server: bool) -> Self {
        let mut res = SupportVersions::new();
        let mut index = 0;
        if !server {
            res.len = bytes[0];
            index += 1;
        }

        while index < bytes.len() {
            res.versions.push(Version::new(u16::from_be_bytes([bytes[index], bytes[index + 1]])));
            index += 2;
        }
        res
    }

    pub fn len(&self, server: bool) -> usize {
        if !server { self.versions.len() * 2 + 1 } else { self.versions.len() * 2 }
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W, server: bool) -> Result<(), BufferError> {
        if !server {
            writer.write_u8(self.len(server) as u8 - 1)?;
        }
        for version in self.versions {
            writer.write_u16(version.into_inner())?;
        }
        Ok(())
    }

    pub fn remove_tls13(&mut self) {
        let pos = self.versions.iter().position(|x| x == &Version::TLS_1_3);
        if let Some(pos) = pos {
            self.versions.remove(pos);
        }
    }

    pub fn versions(&self) -> &Vec<Version> { &self.versions }

    pub fn set_versions(&mut self, versions: Vec<Version>) { self.versions = versions }

    pub fn clear(&mut self) {
        self.versions.clear();
    }

    pub fn push(&mut self, version: Version) {
        self.versions.push(version);
    }
}
