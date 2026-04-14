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
    c_hs_traffic: [u8; 48],
    s_hs_traffic: [u8; 48],
    c_ap_traffic: [u8; 48],
    s_ap_traffic: [u8; 48],
    size: usize,
}

impl TrafficSecret {
    pub fn c_hs_traffic(&self) -> &[u8] {
        &self.c_hs_traffic[..self.size]
    }

    pub fn c_hs_traffic_mut(&mut self) -> &mut [u8] {
        &mut self.c_hs_traffic[..self.size]
    }

    pub fn s_hs_traffic(&self) -> &[u8] {
        &self.s_hs_traffic[..self.size]
    }

    pub fn s_hs_traffic_mut(&mut self) -> &mut [u8] {
        &mut self.s_hs_traffic[..self.size]
    }

    pub fn c_ap_traffic(&self) -> &[u8] {
        &self.c_ap_traffic[..self.size]
    }

    pub fn c_ap_traffic_mut(&mut self) -> &mut [u8] {
        &mut self.c_ap_traffic[..self.size]
    }

    pub fn s_ap_traffic(&self) -> &[u8] {
        &self.s_ap_traffic[..self.size]
    }

    pub fn s_ap_traffic_mut(&mut self) -> &mut [u8] {
        &mut self.s_ap_traffic[..self.size]
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
    const SHA256_SECRET: [u8; 32] = [227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174, 65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85];
    const SHA384_SECRET: [u8; 48] = [56, 176, 96, 167, 81, 172, 150, 56, 76, 217, 50, 126, 177, 177, 227, 106, 33, 253, 183, 17, 20, 190, 7, 67, 76, 12, 199, 191, 99, 246, 225, 218, 39, 78, 222, 191, 231, 111, 101, 251, 213, 26, 210, 241, 72, 152, 185, 91];
    pub fn new(client_random: [u8; 32], server_random: [u8; 32]) -> Self {
        DerivedKey {
            prf: Prf::default(),
            hash: HashType::Sha256,
            master_secret: [0; 48],
            client_random,
            server_random,
            use_ems: false,
            traffic_secret: TrafficSecret {
                c_hs_traffic: [0; 48],
                s_hs_traffic: [0; 48],
                c_ap_traffic: [0; 48],
                s_ap_traffic: [0; 48],
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
        let mut derived_hkdf = Hkdf::new(&[], &vec![0; self.hash.hash_size()], self.hash)?;
        let mut derived = vec![0; self.hash.hash_size()];
        match self.hash {
            HashType::Sha256 => derived_hkdf.hkdf("tls13 derived", &DerivedKey::SHA256_SECRET, &mut derived)?,
            HashType::Sha384 => derived_hkdf.hkdf("tls13 derived", &DerivedKey::SHA384_SECRET, &mut derived)?,
            _ => return Err("Unknown hash secret key".into())
        }
        println!("derived: {:?}", derived);
        //client handshake traffic
        let mut hkdf = Hkdf::new(&derived, &share_secret, self.hash)?;
        hkdf.hkdf("tls13 c hs traffic", session_hash, self.traffic_secret.c_hs_traffic_mut())?;
        let mut f = OpenOptions::new().create(true).append(true).open("2.log")?;
        f.write_all(format!("CLIENT_HANDSHAKE_TRAFFIC_SECRET {} {}\r\n", hex::encode(self.client_random.as_ref()), hex::encode(self.traffic_secret.c_hs_traffic())).as_bytes())?;
        println!("client traffic: {:?}", &self.traffic_secret.c_hs_traffic());
        //server handshake traffic
        // let mut hkdf = Hkdf::new(&derived, &share_secret, self.hash)?;
        let out = self.traffic_secret.s_hs_traffic_mut();
        hkdf.hkdf("tls13 s hs traffic", session_hash, out)?;
        self.prk = hkdf.into_prk().to_vec();
        println!("server traffic: {:?}", out);
        f.write_all(format!("SERVER_HANDSHAKE_TRAFFIC_SECRET {} {}\r\n", hex::encode(self.client_random.as_ref()), hex::encode(out)).as_bytes())?;
        Ok(())
    }

    pub fn make_application_traffic_secret(&mut self, session_hash: &[u8]) -> RlsResult<()> {
        let mut hkdf = Hkdf::from_prk(&self.prk, self.hash);
        let mut salt = vec![0; self.hash.hash_size()];
        match self.hash {
            HashType::Sha256 => hkdf.hkdf("tls13 derived", &Self::SHA256_SECRET, &mut salt).unwrap(),
            HashType::Sha384 => hkdf.hkdf("tls13 derived", &Self::SHA384_SECRET, &mut salt).unwrap(),
            _ => return Err("Unknown hash secret key".into())
        }

        println!("salt: {:?}", salt);

        let mut hkdf = Hkdf::new(&salt, &vec![0; self.hash.hash_size()], self.hash).unwrap();
        hkdf.hkdf("tls13 c ap traffic", session_hash, self.traffic_secret.c_ap_traffic_mut())?;
        let mut f = OpenOptions::new().create(true).append(true).open("2.log")?;
        f.write_all(format!("CLIENT_TRAFFIC_SECRET_0 {} {}\r\n", hex::encode(self.client_random.as_ref()), hex::encode(self.traffic_secret.c_ap_traffic())).as_bytes())?;
        println!("client application traffic: {:?}", &self.traffic_secret.c_ap_traffic());

        hkdf.hkdf("tls13 s ap traffic", session_hash, self.traffic_secret.s_ap_traffic_mut())?;
        f.write_all(format!("SERVER_TRAFFIC_SECRET_0 {} {}\r\n", hex::encode(self.client_random.as_ref()), hex::encode(self.traffic_secret.s_ap_traffic())).as_bytes())?;
        println!("server application traffic: {:?}", &self.traffic_secret.s_ap_traffic());
        Ok(())
    }

    pub fn make_tls13_finish(&mut self, server: bool, session_hash: &[u8]) -> RlsResult<Vec<u8>> {
        let traffic_secret = match server {
            true => self.traffic_secret.s_hs_traffic(),
            false => self.traffic_secret.c_hs_traffic()
        };
        let mut hkdf = Hkdf::from_prk(traffic_secret, self.hash);
        let mut out = vec![0; self.hash.hash_size()];
        hkdf.hkdf("tls13 finished", &[], &mut out)?;
        let mut hmac = Hmac::new(out, self.hash)?;
        hmac.update(session_hash)?;
        Ok(hmac.finalize()?.to_vec())
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

    pub fn make_tls13_cipher_key(&mut self, handshake: bool) -> RlsResult<&KeyBlock> {
        let client_traffic_secret = match handshake {
            true => self.traffic_secret.c_hs_traffic(),
            false => self.traffic_secret.c_ap_traffic()
        };
        //client key
        let mut hkdf = Hkdf::from_prk(client_traffic_secret, self.hash);
        hkdf.hkdf("tls13 key", &[], self.key_block.client_key_mut())?;
        //client iv
        hkdf.hkdf("tls13 iv", &[], self.key_block.client_iv_mut())?;

        let server_traffic_secret = match handshake {
            true => self.traffic_secret.s_hs_traffic(),
            false => self.traffic_secret.s_ap_traffic()
        };
        //server key
        let mut hkdf = Hkdf::from_prk(server_traffic_secret, self.hash);
        hkdf.hkdf("tls13 key", &[], self.key_block.server_key_mut())?;
        //server iv
        hkdf.hkdf("tls13 iv", &[], self.key_block.server_iv_mut())?;
        Ok(&self.key_block)
    }


    pub fn make_cipher_key(&mut self, version: &Version, server: bool) -> RlsResult<Key<'_>> {
        match *version {
            Version::TLS_1_2 => Ok(self.make_tls12_cipher_key()?.get_side(version, server)),
            Version::TLS_1_3 => Ok(self.make_tls13_cipher_key(false)?.get_side(version, server)),
            _ => Err(HandShakeError::UnsupportedVersion(*version).into()),
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