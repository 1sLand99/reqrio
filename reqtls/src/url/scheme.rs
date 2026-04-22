use super::error::UrlError;
use std::fmt::Display;

#[derive(Eq, PartialEq, Debug, Clone, Copy)]
pub enum Scheme {
    Http,
    Https,
    Ws,
    Wss,
    Socks5,
    Trojan,
}

impl Scheme {
    pub fn default_port(&self) -> u16 {
        match self {
            Scheme::Http => 80,
            Scheme::Https => 443,
            Scheme::Ws => 80,
            Scheme::Wss => 443,
            Scheme::Socks5 => 8888,
            Scheme::Trojan => 8888
        }
    }

    pub fn spec(&self) -> &str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
            Scheme::Ws => "ws",
            Scheme::Wss => "wss",
            Scheme::Socks5 => "socks5",
            Scheme::Trojan => "trojan"
        }
    }
}


impl Display for Scheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.spec())
    }
}

impl TryFrom<&str> for Scheme {
    type Error = UrlError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "http" => Ok(Scheme::Http),
            "https" => Ok(Scheme::Https),
            "ws" => Ok(Scheme::Ws),
            "wss" => Ok(Scheme::Wss),
            "socks5" => Ok(Scheme::Socks5),
            "trojan" => Ok(Scheme::Trojan),
            _ => Err(UrlError::InvalidScheme(value.to_string())),
        }
    }
}