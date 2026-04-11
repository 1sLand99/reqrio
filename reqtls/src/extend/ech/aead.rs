#[derive(Debug, Clone, Copy)]
#[allow(non_camel_case_types)]
pub enum Aead {
    AES_128_GCM = 0x1,
    AES_256_GCM = 0x2,
    ChaCha20_POLY1305 = 0x3,
    AES_128_CCM = 0x4,
    AES_128_CCM_8 = 0x5,
    AES_128_CBC_SHA,
    AES_256_CBC_SHA,
}

impl Aead {
    pub(crate) fn from_u16(v: u16) -> Option<Aead> {
        match v {
            0x01 => Some(Aead::AES_128_GCM),
            0x02 => Some(Aead::AES_256_GCM),
            0x03 => Some(Aead::ChaCha20_POLY1305),
            0x04 => Some(Aead::AES_128_CCM),
            0x05 => Some(Aead::AES_128_CCM_8),
            _ => None
        }
    }

    pub fn from_cipher_kind(suite_spec: &str) -> Option<Aead> {
        let text = suite_spec.to_lowercase();
        if text.contains("aes_128_gcm") {
            Some(Aead::AES_128_GCM)
        } else if text.contains("aes_256_gcm") {
            Some(Aead::AES_256_GCM)
        } else if text.contains("chacha20_poly1305") {
            Some(Aead::ChaCha20_POLY1305)
        } else if text.contains("aes_128_cbc") {
            Some(Aead::AES_128_CBC_SHA)
        } else if text.contains("aes_256_cbc") {
            Some(Aead::AES_256_CBC_SHA)
        } else {
            println!("{}", text);
            None
        }
    }

    pub fn mac_key_len(&self) -> usize {
        match self {
            Aead::AES_128_CBC_SHA | Aead::AES_256_CBC_SHA => 20,
            _ => 0
        }
    }

    pub fn key_len(&self) -> usize {
        match self {
            Aead::AES_128_GCM => 16,
            Aead::AES_256_GCM => 32,
            Aead::ChaCha20_POLY1305 => 32,
            Aead::AES_128_CBC_SHA => 16,
            Aead::AES_256_CBC_SHA => 32,
            _ => 0
        }
    }

    pub fn fix_iv_len(&self) -> usize {
        match self {
            Aead::AES_128_GCM | Aead::AES_256_GCM => 4,
            Aead::ChaCha20_POLY1305 => 12,
            Aead::AES_128_CBC_SHA | Aead::AES_256_CBC_SHA => 16,
            _ => 0
        }
    }

    pub fn explicit_len(&self) -> usize {
        match self {
            Aead::AES_128_GCM | Aead::AES_256_GCM => 8,
            Aead::ChaCha20_POLY1305 => 0,
            Aead::AES_128_CBC_SHA | Aead::AES_256_CBC_SHA => 16,
            _ => 0
        }
    }
}