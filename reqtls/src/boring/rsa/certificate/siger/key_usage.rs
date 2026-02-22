pub enum KeyUsage {
    Critical,
    KeyCertSign,
    CrlSign,
    DigitalSignature,
    KeyEncipherment,
    ServerAuth,
    ClientAuth,
    NonRepudiation,
}

impl KeyUsage {
    pub(crate) fn value(&self) -> &str {
        match self {
            KeyUsage::Critical => "critical",
            KeyUsage::KeyCertSign => "keyCertSign",
            KeyUsage::CrlSign => "cRLSign",
            KeyUsage::DigitalSignature => "digitalSignature",
            KeyUsage::KeyEncipherment => "keyEncipherment",
            KeyUsage::ServerAuth => "serverAuth",
            KeyUsage::ClientAuth => "clientAuth",
            KeyUsage::NonRepudiation => "nonRepudiation"
        }
    }
}