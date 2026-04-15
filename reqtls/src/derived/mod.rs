mod block;

use crate::error::{HandShakeError, RlsResult};
use crate::extend::Aead;
use crate::hkdf::Hkdf;
use crate::prf::Prf;
use crate::{HashType, Hasher, Hmac, Version};
pub use block::Key;
use block::KeyBlock;
use std::fs::OpenOptions;
use std::io::Write;


pub struct TrafficSecret {
    client_traffic: [u8; 48],
    server_traffic: [u8; 48],
    size: usize,
}

impl TrafficSecret {
    pub fn client_traffic(&self) -> &[u8] {
        &self.client_traffic[..self.size]
    }

    pub fn client_traffic_mut(&mut self) -> &mut [u8] {
        &mut self.client_traffic[..self.size]
    }

    pub fn server_traffic(&self) -> &[u8] {
        &self.server_traffic[..self.size]
    }

    pub fn server_traffic_mut(&mut self) -> &mut [u8] {
        &mut self.server_traffic[..self.size]
    }
}


pub struct DerivedKey {
    prf: Prf,
    hash: HashType,
    master_secret: [u8; 48],
    client_random: [u8; 32],
    server_random: [u8; 32],
    use_ems: bool,
    traffic_secret: TrafficSecret,
    key_block: KeyBlock,
    prk: Vec<u8>,
}

impl DerivedKey {
    pub fn new(client_random: [u8; 32], server_random: [u8; 32]) -> Self {
        DerivedKey {
            prf: Prf::default(),
            hash: HashType::Sha256,
            master_secret: [0; 48],
            client_random,
            server_random,
            use_ems: false,
            traffic_secret: TrafficSecret {
                client_traffic: [0; 48],
                server_traffic: [0; 48],
                size: 32,
            },
            key_block: KeyBlock::default(),
            prk: vec![],
        }
    }


    pub fn init(&mut self, aead: &Aead, hasher: &Hasher, version: &Version) {
        self.prf = Prf::from_hasher(hasher);
        self.hash = *hasher.hash_type();
        self.traffic_secret.size = self.hash.hash_size();
        self.key_block.init(aead, version);
    }

    ///gen tls 1.2 master secret key
    fn make_tls12_master(&mut self, share_secret: Vec<u8>, session_hash: &[u8]) -> RlsResult<()> {
        let (label, seed) = match self.use_ems {
            true => ("extended master secret", session_hash.to_vec()),
            false => ("master secret", [self.client_random, self.server_random].concat())
        };
        self.prf.prf(&share_secret, label, &seed, &mut self.master_secret)?;
        let mut f = OpenOptions::new().create(true).append(true).open("2.log")?;
        f.write_all(format!("CLIENT_RANDOM {} {}\r\n", hex::encode(self.client_random.as_ref()), hex::encode(self.master_secret)).as_bytes())?;
        Ok(())
    }

    pub fn make_handshake_traffic_secret(&mut self, share_secret: Vec<u8>, session_hash: &[u8]) -> RlsResult<()> {
        let mut derived_hkdf = Hkdf::new(&[], &self.master_secret[..self.hash.hash_size()], self.hash)?;
        let mut derived = vec![0; self.hash.hash_size()];
        derived_hkdf.hkdf("tls13 derived", self.hash.tls13_secret()?, &mut derived)?;
        //client handshake traffic
        let mut hkdf = Hkdf::new(&derived, &share_secret, self.hash)?;
        hkdf.hkdf("tls13 c hs traffic", session_hash, self.traffic_secret.client_traffic_mut())?;
        let mut f = OpenOptions::new().create(true).append(true).open("2.log")?;
        f.write_all(format!("CLIENT_HANDSHAKE_TRAFFIC_SECRET {} {}\r\n", hex::encode(self.client_random.as_ref()), hex::encode(self.traffic_secret.client_traffic())).as_bytes())?;
        //server handshake traffic
        hkdf.hkdf("tls13 s hs traffic", session_hash, self.traffic_secret.server_traffic_mut())?;
        self.prk = hkdf.into_prk().to_vec();
        f.write_all(format!("SERVER_HANDSHAKE_TRAFFIC_SECRET {} {}\r\n", hex::encode(self.client_random.as_ref()), hex::encode(self.traffic_secret.server_traffic())).as_bytes())?;
        Ok(())
    }

    pub fn make_application_traffic_secret(&mut self, session_hash: &[u8]) -> RlsResult<()> {
        let mut hkdf = Hkdf::from_prk(&self.prk, self.hash);
        let mut salt = vec![0; self.hash.hash_size()];
        hkdf.hkdf("tls13 derived", self.hash.tls13_secret()?, &mut salt)?;
        let mut hkdf = Hkdf::new(&salt, &self.master_secret[..self.hash.hash_size()], self.hash)?;
        hkdf.hkdf("tls13 c ap traffic", session_hash, self.traffic_secret.client_traffic_mut())?;
        let mut f = OpenOptions::new().create(true).append(true).open("2.log")?;
        f.write_all(format!("CLIENT_TRAFFIC_SECRET_0 {} {}\r\n", hex::encode(self.client_random.as_ref()), hex::encode(self.traffic_secret.client_traffic())).as_bytes())?;

        hkdf.hkdf("tls13 s ap traffic", session_hash, self.traffic_secret.server_traffic_mut())?;
        f.write_all(format!("SERVER_TRAFFIC_SECRET_0 {} {}\r\n", hex::encode(self.client_random.as_ref()), hex::encode(self.traffic_secret.server_traffic())).as_bytes())?;
        Ok(())
    }

    ///make tls1.2 finish verify data, here use tls1.2 master secret as buffer,
    fn make_tls13_finish(&mut self, server: bool, session_hash: &[u8]) -> RlsResult<Vec<u8>> {
        let traffic_secret = match server {
            true => self.traffic_secret.server_traffic(),
            false => self.traffic_secret.client_traffic()
        };
        let mut hkdf = Hkdf::from_prk(traffic_secret, self.hash);
        let mut out = vec![0; self.hash.hash_size() + 4];
        out[0] = 20;
        out[3] = self.hash.hash_size() as u8;
        hkdf.hkdf("tls13 finished", &[], &mut out[4..])?;
        let mut hmac = Hmac::new(&out[4..], self.hash)?;
        hmac.update(session_hash)?;
        hmac.finalize_extract(&mut out[4..])?;
        Ok(out)
    }

    fn make_tls12_finish(&mut self, server: bool, session_hash: &[u8]) -> RlsResult<Vec<u8>> {
        let mut finish = vec![0; 16];
        finish[0..4].copy_from_slice(&[0x14, 0x00, 0x0, 0xc]);
        let label = if !server { "client finished" } else { "server finished" };
        self.prf.prf(&self.master_secret, label, session_hash, &mut finish[4..16])?;
        Ok(finish)
    }

    pub fn make_master(&mut self, version: Version, share_secret: Vec<u8>, session_hash: &[u8]) -> RlsResult<()> {
        match version {
            Version::TLS_1_2 => self.make_tls12_master(share_secret, session_hash),
            Version::TLS_1_3 => Ok(()),
            _ => Err(HandShakeError::UnsupportedVersion(version).into()),
        }
    }

    fn make_tls12_cipher_key(&mut self) -> RlsResult<&KeyBlock> {
        let seed = [self.server_random, self.client_random].concat();
        self.prf.prfs(&self.master_secret, "key expansion", &seed, self.key_block.bufs())?;
        Ok(&self.key_block)
    }

    pub fn make_tls13_cipher_key(&mut self) -> RlsResult<&KeyBlock> {
        //client
        let mut hkdf = Hkdf::from_prk(self.traffic_secret.client_traffic(), self.hash);
        hkdf.hkdf("tls13 key", &[], self.key_block.client_key_mut())?;
        hkdf.hkdf("tls13 iv", &[], self.key_block.client_iv_mut())?;
        //server
        let mut hkdf = Hkdf::from_prk(self.traffic_secret.server_traffic(), self.hash);
        hkdf.hkdf("tls13 key", &[], self.key_block.server_key_mut())?;
        hkdf.hkdf("tls13 iv", &[], self.key_block.server_iv_mut())?;
        Ok(&self.key_block)
    }


    pub fn make_cipher_key(&mut self, version: &Version, server: bool) -> RlsResult<Key<'_>> {
        Ok(match *version {
            Version::TLS_1_2 => self.make_tls12_cipher_key()?,
            Version::TLS_1_3 => self.make_tls13_cipher_key()?,
            _ => return Err(HandShakeError::UnsupportedVersion(*version).into()),
        }.get_side(version, server))
    }


    pub fn make_finish(&mut self, version: Version, server: bool, session_hash: &[u8]) -> RlsResult<Vec<u8>> {
        match version {
            Version::TLS_1_2 => self.make_tls12_finish(server, session_hash),
            Version::TLS_1_3 => self.make_tls13_finish(server, session_hash),
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