use super::super::version::Version;

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

    pub fn as_bytes(&self, server: bool) -> Vec<u8> {
        let mut res = vec![0];
        for version in &self.versions {
            res.extend(version.as_bytes());
        }
        res[0] = (res.len() - 1) as u8;
        if server { res.remove(0); }
        res
    }

    pub fn remove_tls13(&mut self) {
        let pos = self.versions.iter().position(|x| x == &Version::TLS_1_3);
        if let Some(pos) = pos {
            self.versions.remove(pos);
        }
    }

    pub fn versions(&self) -> &Vec<Version> { &self.versions }

    pub fn push(&mut self, version: Version) {
        self.versions.push(version);
    }
}
