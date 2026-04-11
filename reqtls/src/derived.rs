use crate::error::{HandShakeError, RlsResult};
use crate::extend::Aead;
use crate::prf::Prf;
use crate::{Hasher, ReadExt, Reader, Version};
use std::fs::OpenOptions;
use std::io::Write;

pub enum Key<'a> {
    TLS12 {
        send_mac: &'a [u8],
        recv_mac: &'a [u8],
        send_key: &'a [u8],
        send_iv: &'a [u8],
        recv_key: &'a [u8],
        recv_iv: &'a [u8],
        explicit: &'a [u8],
    }
}

pub struct DerivedKey {
    prf: Prf,
    master_secret: [u8; 48],
    client_random: [u8; 32],
    server_random: [u8; 32],
    use_ems: bool,
    key_block: [u8; 256],
}

impl DerivedKey {
    pub fn new(client_random: [u8; 32], server_random: [u8; 32]) -> Self {
        DerivedKey {
            prf: Prf::default(),
            master_secret: [0; 48],
            client_random,
            server_random,
            use_ems: false,
            key_block: [0; 256],

        }
    }


    pub fn init(&mut self, hasher: &Hasher) {
        self.prf = Prf::from_hasher(hasher);
    }

    fn make_master_tls12(&mut self, share_secret: Vec<u8>, session_hash: &[u8]) -> RlsResult<()> {
        let (label, seed) = match self.use_ems {
            true => ("extended master secret", session_hash.to_vec()),
            false => ("master secret", [self.client_random, self.server_random].concat())
        };
        self.prf.prf(&share_secret, label, &seed, &mut self.master_secret)?;
        let mut f = OpenOptions::new().create(true).append(true).open("2.log")?;
        f.write_all(format!("CLIENT_RANDOM {} {}\r\n", hex::encode(self.client_random.as_ref()), hex::encode(self.master_secret)).as_bytes())?;
        Ok(())
    }

    pub fn make_master(&mut self, version: Version, share_secret: Vec<u8>, session_hash: &[u8]) -> RlsResult<()> {
        match version {
            Version::TLS_1_2 => self.make_master_tls12(share_secret, session_hash),
            Version::TLS_1_3 => self.make_master_tls12(share_secret, session_hash),
            _ => Err(HandShakeError::UnsupportedVersion(version).into()),
        }
    }

    fn mask_tls12_cipher_key(&mut self, aead: &Aead, server: bool) -> RlsResult<Key<'_>> {
        let block_size = (aead.mac_key_len() + aead.key_len() + aead.fix_iv_len()) * 2 + aead.explicit_len();
        let seed = [self.server_random, self.client_random].concat();
        self.prf.prf(&self.master_secret, "key expansion", &seed, &mut self.key_block[..block_size])?;
        let reader = Reader::from_slice(&self.key_block[..block_size]);
        match server {
            false => Ok(Key::TLS12 {
                send_mac: reader.read_slice(aead.mac_key_len())?,
                recv_mac: reader.read_slice(aead.mac_key_len())?,
                send_key: reader.read_slice(aead.key_len())?,
                recv_key: reader.read_slice(aead.key_len())?,
                send_iv: reader.read_slice(aead.fix_iv_len())?,
                recv_iv: reader.read_slice(aead.fix_iv_len())?,
                explicit: reader.read_slice(aead.explicit_len())?,
            }),
            true => Ok(Key::TLS12 {
                recv_mac: reader.read_slice(aead.mac_key_len())?,
                send_mac: reader.read_slice(aead.mac_key_len())?,
                recv_key: reader.read_slice(aead.key_len())?,
                send_key: reader.read_slice(aead.key_len())?,
                recv_iv: reader.read_slice(aead.fix_iv_len())?,
                send_iv: reader.read_slice(aead.fix_iv_len())?,
                explicit: reader.read_slice(aead.explicit_len())?,
            })
        }
    }

    pub fn make_cipher_key(&mut self, version: Version, aead: &Aead, server: bool) -> RlsResult<Key<'_>> {
        match version {
            Version::TLS_1_2 => self.mask_tls12_cipher_key(aead, server),
            // Version::TLS_1_3 => self.make_master_tls12(share_secret, session_hash),
            _ => Err(HandShakeError::UnsupportedVersion(version).into()),
        }
    }


    pub fn make_finish(&mut self, version: Version, label: &str, session_hash: &[u8], out: &mut [u8]) -> RlsResult<()> {
        match version {
            Version::TLS_1_2 => self.prf.prf(&self.master_secret, label, session_hash, out),
            // Version::TLS_1_3 => self.make_master_tls12(share_secret, session_hash),
            _ => Err(HandShakeError::UnsupportedVersion(version).into()),
        }
    }

    pub fn set_client_random(&mut self, client_random: [u8; 32]) {
        self.client_random = client_random;
    }

    pub fn set_server_random(&mut self, server_random: [u8; 32]) {
        self.server_random = server_random;
    }

    pub fn client_random(&self) -> &[u8] {
        &self.client_random
    }

    pub fn server_random(&self) -> &[u8] {
        &self.server_random
    }

    pub fn set_ems(&mut self, ems: bool) {
        self.use_ems = ems
    }
}