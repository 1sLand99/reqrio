use crate::extend::Aead;
use crate::Version;

#[derive(Debug)]
pub enum Key<'a> {
    TLS12 {
        send_mac: &'a [u8],
        recv_mac: &'a [u8],
        send_key: &'a [u8],
        send_iv: &'a [u8],
        recv_key: &'a [u8],
        recv_iv: &'a [u8],
        explicit: &'a [u8],
    },
    TLS13 {
        send_key: &'a [u8],
        recv_key: &'a [u8],
        send_iv: &'a [u8],
        recv_iv: &'a [u8],
    },
}


pub(crate) struct KeyBlock {
    client_mac_key: [u8; 20],
    server_mac_key: [u8; 20],
    mac_size: usize,
    client_key: [u8; 32],
    server_key: [u8; 32],
    key_size: usize,
    client_iv: [u8; 16],
    server_iv: [u8; 16],
    ///tls12: fix iv;
    iv_size: usize,
    explicit: [u8; 16],
    explicit_len: usize,
}

impl Default for KeyBlock {
    fn default() -> Self {
        KeyBlock {
            client_mac_key: [0; 20],
            server_mac_key: [0; 20],
            mac_size: 20,
            client_key: [0; 32],
            server_key: [0; 32],
            key_size: 32,
            client_iv: [0; 16],
            server_iv: [0; 16],
            iv_size: 16,
            explicit: [0; 16],
            explicit_len: 0,
        }
    }
}

impl KeyBlock {
    pub fn init(&mut self, aead: &Aead, version: &Version) {
        self.mac_size = aead.mac_key_len();
        self.key_size = aead.key_len();
        self.iv_size = aead.fix_iv_len(version);
        self.explicit_len = aead.explicit_len(version)
    }

    pub fn client_mac_key(&self) -> &[u8] {
        &self.client_mac_key[..self.mac_size]
    }

    pub fn server_mac_key(&self) -> &[u8] {
        &self.server_mac_key[..self.mac_size]
    }

    pub fn client_key(&self) -> &[u8] {
        &self.client_key[..self.key_size]
    }

    pub fn client_key_mut(&mut self) -> &mut [u8] {
        &mut self.client_key[..self.key_size]
    }

    pub fn server_key(&self) -> &[u8] {
        &self.server_key[..self.key_size]
    }

    pub fn server_key_mut(&mut self) -> &mut [u8] {
        &mut self.server_key[..self.key_size]
    }

    pub fn client_iv(&self) -> &[u8] {
        &self.client_iv[..self.iv_size]
    }

    pub fn client_iv_mut(&mut self) -> &mut [u8] {
        &mut self.client_iv[..self.iv_size]
    }

    pub fn server_iv(&self) -> &[u8] {
        &self.server_iv[..self.iv_size]
    }

    pub fn server_iv_mut(&mut self) -> &mut [u8] {
        &mut self.server_iv[..self.iv_size]
    }

    pub fn explicit(&self) -> &[u8] {
        &self.explicit[..self.explicit_len]
    }

    pub fn bufs(&mut self) -> Vec<&mut [u8]> {
        vec![
            &mut self.client_mac_key[..self.mac_size],
            &mut self.server_mac_key[..self.mac_size],
            &mut self.client_key[..self.key_size],
            &mut self.server_key[..self.key_size],
            &mut self.client_iv[..self.iv_size],
            &mut self.server_iv[..self.iv_size],
            &mut self.explicit[..self.explicit_len],
        ]
    }

    pub fn get_side(&self, version: &Version, server: bool) -> Key<'_> {
        match server {
            false => match *version {
                Version::TLS_1_3 => Key::TLS13 {
                    send_key: self.client_key(),
                    send_iv: self.client_iv(),
                    recv_key: self.server_key(),
                    recv_iv: self.server_iv(),
                },
                _ => Key::TLS12 {
                    send_mac: self.client_mac_key(),
                    recv_mac: self.server_mac_key(),
                    send_key: self.client_key(),
                    send_iv: self.client_iv(),
                    recv_key: self.server_key(),
                    recv_iv: self.server_iv(),
                    explicit: self.explicit(),
                }
            },
            true => match *version {
                Version::TLS_1_3 => Key::TLS13 {
                    send_key: self.server_key(),
                    send_iv: self.server_iv(),
                    recv_key: self.client_key(),
                    recv_iv: self.client_iv(),
                },
                _ => Key::TLS12 {
                    send_mac: self.server_mac_key(),
                    recv_mac: self.client_mac_key(),
                    send_key: self.server_key(),
                    send_iv: self.server_iv(),
                    recv_key: self.client_key(),
                    recv_iv: self.client_iv(),
                    explicit: self.explicit(),
                }
            },
        }
    }
}