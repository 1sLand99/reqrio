use reqtls::{Certificate, RsaKey, ALPN};
use crate::Fingerprint;

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
}

pub struct ServerConfig<'a> {
    pub alpn: &'a ALPN,
    pub server_cert: &'a mut Vec<Certificate>,
    pub ca: &'a mut Certificate,
    pub cert_key: &'a RsaKey,
    pub verify: bool,
}