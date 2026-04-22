use std::env;
use std::path::{Path, PathBuf};
use reqtls::{Certificate, RsaKey, ALPN};
use crate::Fingerprint;
use crate::stream::ConnParam;

pub(crate) enum Config<'a> {
    Server(ServerConfig<'a>),
    Client(ClientConfig<'a>),
}

impl<'a> Config<'a> {
    pub fn client_mut(&mut self) -> Option<&mut ClientConfig<'a>> {
        match self {
            Config::Server(_) => None,
            Config::Client(v) => Some(v)
        }
    }

    pub fn server_mut(&mut self) -> Option<&mut ServerConfig<'a>> {
        match self {
            Config::Server(v) => Some(v),
            Config::Client(_) => None
        }
    }
}


pub struct ClientConfig<'a> {
    pub sni: &'a str,
    pub alpn: &'a ALPN,
    pub fingerprint: &'a mut Fingerprint,
    pub client_cert: &'a mut Vec<Certificate>,
    pub cert_key: &'a RsaKey,
    pub verify: bool,
    pub ca_certs: &'a [Certificate],
    pub key_log: Option<PathBuf>,
}

impl<'a> From<ConnParam<'a>> for ClientConfig<'a> {
    fn from(param: ConnParam<'a>) -> Self {
        ClientConfig {
            sni: param.url.sni(),
            alpn: param.alpn,
            fingerprint: param.fingerprint,
            client_cert: param.cert,
            cert_key: param.key,
            verify: param.verify,
            ca_certs: param.ca_cert,
            key_log: param.key_log.clone().or_else(|| match env::var("SSLKEYLOGFILE") {
                Ok(key_log) => Some(Path::new(&key_log).to_path_buf()),
                Err(_) => None
            }),
        }
    }
}

pub struct ServerConfig<'a> {
    pub alpn: &'a ALPN,
    pub server_cert: &'a mut Vec<Certificate>,
    pub ca: &'a mut Certificate,
    pub cert_key: &'a RsaKey,
    pub verify: bool,
    pub ca_certs: &'a Vec<Certificate>,
    pub key_log: Option<PathBuf>,
}