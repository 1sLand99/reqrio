use std::fmt::Debug;
use crate::*;
use crate::packet::H2EncodeFrame;

#[derive(Debug)]
pub struct H2Finger {
    ///SETTING
    pub setting: Vec<H2Setting>,
    ///WINDOW UPDATE: window size increment
    pub window_size: u32,
    ///weight
    pub weight: u8,
    ///priority
    pub priority: bool,
}

impl H2Finger {
    pub fn build_setting(&self) -> H2EncodeFrame<'_> {
        H2EncodeFrame::new_setting(&self.setting)
    }

    pub fn build_window_update(&self) -> H2EncodeFrame<'_> {
        H2EncodeFrame::new_window_update(&self.window_size)
    }

    pub fn add_setting(&mut self, setting: H2Setting) {
        self.setting.push(setting);
    }

    pub fn set_window_size(&mut self, window_size: u32) {
        self.window_size = window_size;
    }

    pub fn set_priority(&mut self, priority: bool, weight: u8) {
        self.priority = priority;
        self.weight = weight;
    }
}

#[derive(Debug)]
pub struct Fingerprint {
    tls: TlsFinger,
    h2: H2Finger,
    legal_subscript: i32,
}

impl Fingerprint {
    pub fn new_custom(token: impl AsRef<str>) -> Fingerprint {
        Fingerprint {
            tls: TlsFinger::Custom { suites: vec![], extensions: vec![] },
            h2: H2Finger {
                setting: vec![],
                window_size: 0,
                weight: 0,
                priority: false,
            },
            legal_subscript: Buffer::new_bytes(vec![]).check_subscription(token).unwrap_or(-2),
        }
    }

    pub fn new(tls: TlsFinger, h2: H2Finger, token: impl AsRef<str>) -> HlsResult<Self> {
        Ok(Fingerprint {
            tls,
            h2,
            legal_subscript: Buffer::with_capacity(1).check_subscription(token)?,
        })
    }

    pub fn new_tls(tls: TlsFinger, token: impl AsRef<str>) -> HlsResult<Self> {
        Ok(Fingerprint {
            tls,
            legal_subscript: Buffer::with_capacity(1).check_subscription(token)?,
            ..Default::default()
        })
    }

    pub fn h2(&self) -> &H2Finger {
        &self.h2
    }

    pub fn h2_mut(&mut self) -> &mut H2Finger {
        &mut self.h2
    }

    pub fn legal_subscript(&self) -> i32 {
        self.legal_subscript
    }

    pub fn tls(&self) -> &TlsFinger { &self.tls }

    pub fn tls_mut(&mut self) -> &mut TlsFinger { &mut self.tls }
}

impl Fingerprint {
    pub fn random(token: impl AsRef<str>) -> Fingerprint {
        Fingerprint {
            tls: TlsFinger::random(),
            legal_subscript: Buffer::with_capacity(0).check_subscription(token).unwrap_or(-2),
            ..Default::default()
        }
    }

    pub fn from_client_hello(ch: Vec<u8>, token: impl AsRef<str>) -> HlsResult<Fingerprint> {
        Ok(Fingerprint {
            tls: TlsFinger::ClientHello(Bytes::new(ch)),
            legal_subscript: Buffer::with_capacity(0).check_subscription(token)?,
            ..Default::default()
        })
    }

    pub fn from_hex_all(hex_str: impl AsRef<str>, token: impl AsRef<str>) -> HlsResult<Fingerprint> {
        let mut client_hello = hex::decode(hex_str.as_ref())?;
        let len = u16::from_be_bytes([client_hello[3], client_hello[4]]) as usize + 5;
        let _ = client_hello.split_off(len);
        Ok(Fingerprint {
            tls: TlsFinger::ClientHello(Bytes::new(client_hello)),
            legal_subscript: Buffer::with_capacity(0).check_subscription(token)?,
            ..Default::default()
        })
    }

    pub fn from_ja3(ja3: impl AsRef<str>, token: impl AsRef<str>) -> HlsResult<Fingerprint> {
        Ok(Fingerprint {
            tls: TlsFinger::from_ja3(ja3)?,
            legal_subscript: Buffer::with_capacity(0).check_subscription(token)?,
            ..Default::default()
        })
    }

    pub fn from_ja4(ja4: impl AsRef<str>, token: impl AsRef<str>) -> HlsResult<Fingerprint> {
        Ok(Fingerprint {
            tls: TlsFinger::from_ja4(ja4)?,
            legal_subscript: Buffer::with_capacity(0).check_subscription(token)?,
            ..Default::default()
        })
    }
}

impl Default for Fingerprint {
    fn default() -> Fingerprint {
        Fingerprint {
            tls: TlsFinger::Default,
            h2: H2Finger {
                setting: vec![
                    H2Setting::HeaderTableSize(65536),
                    H2Setting::EnablePush(0),
                    H2Setting::InitialWindowSize(6291456),
                    H2Setting::MaxHeaderListSize(242144)
                ],
                window_size: 2147418112,
                weight: 147,
                priority: true,
            },
            legal_subscript: -2,
        }
    }
}