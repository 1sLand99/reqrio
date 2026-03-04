use super::error::UrlError;
use std::fmt::Display;

#[derive(Eq, PartialEq, Debug, Clone)]
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
}


impl Display for Scheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Scheme::Http => f.write_str("http"),
            Scheme::Https => f.write_str("https"),
            Scheme::Ws => f.write_str("ws"),
            Scheme::Wss => f.write_str("wss"),
            Scheme::Socks5 => f.write_str("socks5"),
            Scheme::Trojan => f.write_str("trojan")
        }
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