use crate::dns::{DNSCache, DNSStream};
use crate::error::RlsResult;
use crate::url::UrlError;
use std::collections::HashMap;
use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::sync::{Arc, LazyLock, RwLock};
use std::time::SystemTime;

static DNS: LazyLock<RwLock<HashMap<String, Arc<DNSCache>>>> = LazyLock::new(|| RwLock::new(HashMap::new()));


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

    fn get_dns(&self, ech: bool) -> RlsResult<Arc<DNSCache>> {
        let mut cache = match IpAddr::from_str(&self.host) {
            Ok(addr) => DNSCache::new_addrs(vec![addr]),
            Err(_) => {
                let mut cache = if ech {
                    let mut stream = DNSStream::new()?;
                    let cache = stream.get_dns_https(&self.host)?;
                    cache
                } else { DNSCache::new_addrs(vec![]) };
                if cache.addrs().is_empty() {
                    let addrs = format!("{}:{}", self.host, self.port).to_socket_addrs()?.map(|x| x.ip()).collect();
                    cache.set_addrs(addrs);
                }
                cache
            }
        };

        let t = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_secs();
        cache.set_time(t);
        let cache = Arc::new(cache);
        let mut dns_write = DNS.write()?;
        dns_write.insert(self.host.clone(), cache.clone());
        Ok(cache)
    }
    pub fn get_dns_cache(&self, ech: bool) -> RlsResult<Arc<DNSCache>> {
        let dns_read = DNS.read()?;
        match dns_read.get(&self.host) {
            None => {
                drop(dns_read);
                self.get_dns(ech)
            }
            Some(dns) => {
                let t = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_secs();
                if t - dns.time() > 30 * 60 {
                    drop(dns_read);
                    self.get_dns(ech)
                } else {
                    Ok(dns.clone())
                }
            }
        }
    }

    pub fn socket_addr(&self, ech: bool) -> RlsResult<SocketAddr> {
        let dns = self.get_dns_cache(ech)?;
        let addr = dns.addrs().iter().next().ok_or("missing dns address")?;
        Ok(SocketAddr::new(*addr, self.port))
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
    type Error = UrlError;
    fn try_from(value: &str) -> Result<Addr, Self::Error> {
        let host_pos = value.find(':');
        match host_pos {
            None => {
                Ok(Addr {
                    host: value.to_string(),
                    port: 0,
                })
            }
            Some(host_pos) => {
                Ok(Addr {
                    host: value[..host_pos].to_string(),
                    port: value[host_pos + 1..].parse().or(Err(UrlError::InvalidPort(value[host_pos + 1..].to_string())))?,
                })
            }
        }
    }
}

impl TryFrom<String> for Addr {
    type Error = UrlError;
    fn try_from(value: String) -> Result<Addr, UrlError> {
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


#[cfg(test)]
mod tests {
    use crate::Addr;

    #[test]
    fn test_addr() {
        let addr = Addr::new_addr("127.0.0.1", 1234);
        println!("{}", addr.socket_addr(false).unwrap());
    }
}