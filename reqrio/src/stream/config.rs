use crate::stream::ConnParam;
use reqtls::{Certificate, RsaKey, TlsFinger, TlsSession, ALPN};
use std::env;
use std::path::{Path, PathBuf};

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
    ///域名，ServerName
    pub sni: &'a str,
    ///设置应用层使用哪个协议，这里一般设置最高那个
    pub alpn: &'a ALPN,
    ///Tls指纹信息，
    pub fingerprint: &'a mut TlsFinger,
    ///证书，mTls设置客户端证书
    pub client_cert: &'a mut Vec<Certificate>,
    ///证书私钥，mTls设置客户端证书私钥
    pub cert_key: &'a RsaKey,
    ///是否对服务器证书链签名进行校验
    pub verify: bool,
    ///额外的ca证书，用于自签证书
    pub ca_certs: &'a [Certificate],
    ///tls密钥导出路径，None不导出
    pub key_log: Option<PathBuf>,
    ///使用tls会话数据恢复会话
    pub session: &'a Option<TlsSession>,
}

impl<'a> From<ConnParam<'a>> for ClientConfig<'a> {
    fn from(param: ConnParam<'a>) -> Self {
        ClientConfig {
            sni: param.url.sni(),
            alpn: param.alpn,
            fingerprint: param.fingerprint.tls_mut(),
            client_cert: param.cert,
            cert_key: param.key,
            verify: param.verify,
            ca_certs: param.ca_cert,
            key_log: param.key_log.clone().or_else(|| match env::var("SSLKEYLOGFILE") {
                Ok(key_log) => Some(Path::new(&key_log).to_path_buf()),
                Err(_) => None
            }),
            session: param.session,
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