use crate::error::RlsResult;
use crate::RlsError;
use std::fmt::Display;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::vec::IntoIter;
use crate::url::UrlError;

#[derive(Debug, Clone, PartialEq)]
pub struct Addr {
    host: String,
    port: u16,
}

impl Default for Addr {
    fn default() -> Self {
        Addr {
            host: "".to_string(),
            port: 0,
        }
    }
}

impl Addr {

    pub fn new_addr(host: impl ToString, port: u16) -> Addr {
        let mut res = Addr::default();
        res.host = host.to_string();
        res.port = port;
        res
    }

    pub fn new_bits(host: u32, port: u16) -> Addr {
        let mut res = Addr::default();
        let ip = Ipv4Addr::from_bits(host);
        res.host = ip.to_string();
        res.port = port;
        res
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn set_port(&mut self, port: u16) {
        self.port = port;
    }

    pub fn set_host(&mut self, host: impl ToString) {
        self.host = host.to_string();
    }

    pub fn socket_addr(&self) -> RlsResult<IntoIter<SocketAddr>> {
        Ok(self.to_string().to_socket_addrs()?)
    }

    pub fn socket_addr_v4(&self) -> RlsResult<SocketAddr> {
        let addr = self.socket_addr()?.find(|x| x.is_ipv4()).ok_or("not found ipv4")?;
        Ok(addr)
    }

    pub fn socket_addr_v6(&self) -> RlsResult<SocketAddr> {
        let addr = self.socket_addr()?.find(|x| x.is_ipv6()).ok_or("not found ipv6")?;
        Ok(addr)
    }

    pub fn to_bits(&self) -> RlsResult<u32> {
        Ok(Ipv4Addr::from_str(self.host())?.to_bits())
    }
}

impl Display for Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}:{}", self.host, self.port))
    }
}

impl TryFrom<&str> for Addr {
    type Error = RlsError;
    fn try_from(value: &str) -> RlsResult<Addr> {
        let mut i = value.split(':');
        let mut res = Addr::default();
        res.host = i.next().ok_or(UrlError::MissingDomain)?.to_string();
        if let Some(port) = i.next() {
            res.port = port.parse().or(Err(UrlError::InvalidPort))?;
        }
        Ok(res)
    }
}

impl TryFrom<String> for Addr {
    type Error = RlsError;
    fn try_from(value: String) -> RlsResult<Addr> {
        Addr::try_from(value.as_str())
    }
}


impl From<SocketAddr> for Addr {
    fn from(value: SocketAddr) -> Self {
        Addr {
            host: value.ip().to_string(),
            port: value.port(),
        }
    }
}