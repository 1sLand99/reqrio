use std::fmt::Display;

#[derive(Eq, PartialEq, Debug, Clone)]
pub enum Scheme {
    Http,
    Https,
    Ws,
    Wss,
    Socks5,
    Trojan,
    Custom(String),
}

impl Scheme {
    pub fn default_port(&self) -> u16 {
        match self {
            Scheme::Http => 80,
            Scheme::Https => 443,
            Scheme::Ws => 80,
            Scheme::Wss => 443,
            Scheme::Socks5 => 8888,
            Scheme::Trojan => 8888,
            Scheme::Custom(_) => 0
        }
    }

    pub fn spec(&self) -> &str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
            Scheme::Ws => "ws",
            Scheme::Wss => "wss",
            Scheme::Socks5 => "socks5",
            Scheme::Trojan => "trojan",
            Scheme::Custom(s) => s
        }
    }
}


impl Display for Scheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.spec())
    }
}


impl PartialEq<Option<Scheme>> for Scheme {
    fn eq(&self, other: &Option<Scheme>) -> bool {
        if let Some(other) = other {
            self == other
        } else { false }
    }
}

impl PartialEq<Option<Scheme>> for &Scheme {
    fn eq(&self, other: &Option<Scheme>) -> bool {
        if let Some(other) = other {
            self == &other
        } else { false }
    }
}
impl From<&str> for Scheme {
    fn from(value: &str) -> Self {
        match value {
            "http" => Scheme::Http,
            "https" => Scheme::Https,
            "ws" => Scheme::Ws,
            "wss" => Scheme::Wss,
            "socks5" => Scheme::Socks5,
            "trojan" => Scheme::Trojan,
            _ => Scheme::Custom(value.to_string()),
        }
    }
}