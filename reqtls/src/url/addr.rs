use std::collections::HashMap;
use crate::error::RlsResult;
use crate::RlsError;
use std::fmt::Display;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::sync::{LazyLock, RwLock};
use std::time::SystemTime;
use std::vec::IntoIter;
use crate::url::UrlError;

static  DNS: LazyLock<RwLock<HashMap<String, DNSCache>>> = LazyLock::new(|| RwLock::new(HashMap::new()));

struct DNSCache {
    route: IntoIter<SocketAddr>,
    time: u64,
}

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
        Addr {
            host: host.to_string(),
            port,
        }
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

    fn get_dns(&self) -> RlsResult<IntoIter<SocketAddr>> {
        let addr = self.to_string().to_socket_addrs()?;
        let mut dns_write =DNS.write()?;
        let t = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_secs();
        dns_write.insert(self.host.clone(), DNSCache {
            route: addr.clone(),
            time: t,
        });
        Ok(addr)
    }
    pub fn socket_addr(&self) -> RlsResult<IntoIter<SocketAddr>> {
        let dns_read = DNS.read()?;
        match dns_read.get(&self.host) {
            None => {
                drop(dns_read);
                self.get_dns()
            }
            Some(dns) => {
                let t = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_secs();
                if t - dns.time > 30 * 60 {
                    drop(dns_read);
                    self.get_dns()
                } else {
                    Ok(dns.route.clone())
                }
            }
        }
    }

    pub fn socket_addr_v4(&self) -> RlsResult<SocketAddr> {
        let mut addr = self.socket_addr()?.find(|x| x.is_ipv4()).ok_or(UrlError::MissingIpv4SocketAddr)?;
        addr.set_port(self.port);
        Ok(addr)
    }

    pub fn socket_addr_v6(&self) -> RlsResult<SocketAddr> {
        let mut addr = self.socket_addr()?.find(|x| x.is_ipv6()).ok_or(UrlError::MissingIpv6SocketAddr)?;
        addr.set_port(self.port);
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
        let mut res = Addr {
            host: i.next().ok_or(UrlError::MissingDomain)?.to_string(),
            port: 0,
        };
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