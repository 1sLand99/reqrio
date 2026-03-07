use crate::error::{HlsError, HlsResult};
use crate::hpack::{HPack, HPackCoding};
use crate::json::JsonValue;
use crate::*;
pub use key::HeaderKey;
pub use method::Method;
pub use status::HttpStatus;
use std::fmt::Display;
use std::mem;
pub use value::HeaderValue;

use super::content_type::ContentType;
use super::cookie::Cookie;

mod value;
mod key;
mod method;
mod status;

#[derive(Clone)]
pub struct Header {
    method: Method,
    alpn: ALPN,
    uri: Uri,
    status: HttpStatus,
    keys: Vec<HeaderKey>,
    hpack_coder: HPackCoding,
}

impl Header {
    pub fn new_res() -> Self {
        Self {
            method: Method::GET,
            alpn: ALPN::Custom(vec![]),
            uri: Uri::default(),
            status: HttpStatus::None,
            keys: vec![],
            hpack_coder: HPackCoding::new(),
        }
    }


    pub fn new_req_h2() -> Self {
        let mut res = Header::new_res();
        res.alpn = ALPN::Http20;
        res.keys = vec![
            //h2 order
            HeaderKey::new("cache-control", HeaderValue::String("".to_string())),
            HeaderKey::new("sec-ch-ua", HeaderValue::String("".to_string())),
            HeaderKey::new("sec-ch-ua-mobile", HeaderValue::String("".to_string())),
            HeaderKey::new("sec-ch-ua-full-version", HeaderValue::String("".to_string())),
            HeaderKey::new("sec-ch-ua-arch", HeaderValue::String("".to_string())),
            HeaderKey::new("sec-ch-ua-platform", HeaderValue::String("".to_string())),
            HeaderKey::new("sec-ch-ua-platform-version", HeaderValue::String("".to_string())),
            HeaderKey::new("sec-ch-ua-model", HeaderValue::String("".to_string())),
            HeaderKey::new("sec-ch-ua-bitness", HeaderValue::String("".to_string())),
            HeaderKey::new("sec-ch-ua-full-version-list", HeaderValue::String("".to_string())),
            HeaderKey::new("upgrade-insecure-requests", HeaderValue::Bool(true)),
            HeaderKey::new("user-agent", HeaderValue::String("".to_string())),
            HeaderKey::new("accept", HeaderValue::String("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7".to_string())),
            HeaderKey::new("origin", HeaderValue::String("".to_string())),
            HeaderKey::new("sec-fetch-site", HeaderValue::String("".to_string())),
            HeaderKey::new("sec-fetch-mode", HeaderValue::String("".to_string())),
            HeaderKey::new("sec-fetch-user", HeaderValue::String("".to_string())),
            HeaderKey::new("sec-fetch-dest", HeaderValue::String("".to_string())),
            HeaderKey::new("sec-fetch-storage-access", HeaderValue::String("".to_string())),
            HeaderKey::new("referer", HeaderValue::String("".to_string())),
            HeaderKey::new("accept-encoding", HeaderValue::String("gzip, deflate, br, zstd".to_string())),
            HeaderKey::new("accept-language", HeaderValue::String("zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6".to_string())),
            HeaderKey::new("cookie", HeaderValue::Cookies(vec![])),
            HeaderKey::new("priority", HeaderValue::String("".to_string())),
            //unknown or http
            HeaderKey::new("content-encoding", HeaderValue::String("".to_string())),
            HeaderKey::new("content-type", HeaderValue::String("".to_string())),
            HeaderKey::new("authorization", HeaderValue::String("".to_string())),
            HeaderKey::new("content-type", HeaderValue::String("".to_string())),
        ];
        res
    }

    pub fn new_req_h1() -> Self {
        let mut res = Header::new_res();
        res.alpn = ALPN::Http11;
        res.keys = vec![
            HeaderKey::new("Host", HeaderValue::String("".to_string())),
            HeaderKey::new("Connection", HeaderValue::String("".to_string())),
            HeaderKey::new("Content-Length", HeaderValue::Number(0)),
            HeaderKey::new("Authorization", HeaderValue::String("".to_string())),
            HeaderKey::new("Content-Type", HeaderValue::String("".to_string())),
            HeaderKey::new("Cache-Control", HeaderValue::String("".to_string())),
            HeaderKey::new("sec-ch-ua", HeaderValue::String("".to_string())),
            HeaderKey::new("sec-ch-ua-mobile", HeaderValue::String("".to_string())),
            HeaderKey::new("sec-ch-ua-platform", HeaderValue::String("".to_string())),
            HeaderKey::new("Upgrade-Insecure-Requests", HeaderValue::Bool(true)),
            HeaderKey::new("User-Agent", HeaderValue::String("".to_string())),
            HeaderKey::new("Accept", HeaderValue::String("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7".to_string())),
            HeaderKey::new("Sec-Fetch-Site", HeaderValue::String("".to_string())),
            HeaderKey::new("Sec-Fetch-Mode", HeaderValue::String("".to_string())),
            HeaderKey::new("Sec-Fetch-User", HeaderValue::String("".to_string())),
            HeaderKey::new("Sec-Fetch-Dest", HeaderValue::String("".to_string())),
            HeaderKey::new("Sec-Fetch-Storage-Access", HeaderValue::String("".to_string())),
            HeaderKey::new("Referer", HeaderValue::String("".to_string())),
            HeaderKey::new("Accept-Encoding", HeaderValue::String("gzip, deflate, br, zstd".to_string())),
            HeaderKey::new("Accept-Language", HeaderValue::String("zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6".to_string())),
            HeaderKey::new("Cookie", HeaderValue::Cookies(vec![])),
            HeaderKey::new("Origin", HeaderValue::String("".to_string())),
            // HeaderKey::new("pragma", HeaderValue::String("".to_string())),

        ];
        res
    }

    pub fn to_req_cookie_str(&self) -> String {
        let header = self.keys.iter().find(|x| x.name_lower() == "cookie");
        if let Some(header) = header && let Some(cookie) = header.cookies() {
            cookie.iter().map(|cookie| cookie.as_req()).collect::<Vec<_>>().join("; ")
        } else {
            "".to_string()
        }
    }

    fn write_h1_buffer<W: WriteExt>(&self, addr: &Addr, len: usize, writer: &mut W) -> HlsResult<usize> {
        // first line: Method uri version
        writer.write_slice(self.method.to_string().as_bytes());
        writer.write_u8(b' ');
        writer.write_slice(self.uri.to_string().as_bytes());
        writer.write_u8(b' ');
        writer.write_slice(self.alpn.to_string().as_bytes());
        writer.write_slice(b"\r\n");
        //header keys
        for key in self.keys.iter() {
            if key.value().is_empty() && key.name().to_lowercase() != "Host" { continue; }
            writer.write_slice(key.name().as_bytes());
            writer.write_slice(b": ");
            match key.name_lower().as_str() {
                "host" => {
                    writer.write_slice(addr.host().as_bytes());
                    if addr.port() != 80 && addr.port() != 443 {
                        writer.write_slice(b":");
                        writer.write_slice(addr.port().to_string().as_bytes());
                    }
                }
                "content-length" => writer.write_slice(len.to_string().as_bytes()),
                "cookie" => {
                    for (index, cookie) in key.cookies().unwrap_or(&vec![]).iter().enumerate() {
                        writer.write_slice(cookie.name().as_bytes());
                        writer.write_u8(b'=');
                        writer.write_slice(cookie.value().as_bytes());
                        if index != key.cookies().unwrap_or(&vec![]).len() - 1 { writer.write_slice(b"; ") }
                    }
                }
                _ => writer.write_slice(key.value().as_string().unwrap_or(&key.value().to_string()).as_bytes()),
            }
            writer.write_slice(b"\r\n");
        }
        Ok(0)
    }

    fn write_h2_buffer<W: WriteExt>(&mut self, addr: &Addr, writer: &mut W) -> HlsResult<usize> {
        let start = writer.offset().end;
        writer.write_slice(&self.hpack_coder.encoder().encode_one(b":method", self.method.to_string())?);
        writer.write_slice(&self.hpack_coder.encoder().encode_one(b":authority", addr.to_string().replace(":80", "").replace(":443", ""))?);
        writer.write_slice(&self.hpack_coder.encoder().encode_one(b":scheme", b"https")?);
        writer.write_slice(&self.hpack_coder.encoder().encode_one(b":path", self.uri.to_string())?);
        let invalid_keys = ["connection", "host", "content-length", "transfer-encoding", "upgrade"];
        let keys = self.keys.iter().filter(|x| !invalid_keys.contains(&x.name_lower().as_str()) && !x.value().is_empty());
        for key in keys {
            let name = key.name_lower();
            match key.value() {
                HeaderValue::Cookies(cookies) => for cookie in cookies {
                    writer.write_slice(&self.hpack_coder.encoder().encode_one(name.to_owned(), cookie.as_req())?)
                }
                _ => writer.write_slice(&self.hpack_coder.encoder().encode_one(name, key.value().to_string())?)
            }
        }
        Ok(writer.offset().end - start)
    }

    pub fn write_to<W: WriteExt>(&mut self, addr: &Addr, len: usize, writer: &mut W) -> HlsResult<usize> {
        match self.alpn {
            ALPN::Http10 | ALPN::Http11 => self.write_h1_buffer(addr, len, writer),
            ALPN::Http20 => self.write_h2_buffer(addr, writer),
            ALPN::Custom(_) => Err("unsupported http protocol".into()),
        }
    }

    pub fn as_raw(&mut self, body_len: usize) -> HlsResult<Vec<String>> {
        self.set_content_length(body_len)?;
        Ok(self.raw(true))
    }

    fn raw(&self, http: bool) -> Vec<String> {
        let mut res = vec![];
        for key in &self.keys {
            if key.value().to_string() == "" && http { continue; }
            match key.name_lower().as_str() {
                "set-cookie" => for cookie in key.cookies().unwrap_or(&vec![]) {
                    res.push(format!("Set-Cookie: {}", cookie.as_res()));
                },
                _ => res.push(format!("{}: {}", key.name(), key.value()))
            }
        }
        res
    }

    pub fn get(&self, name: &str) -> Option<&HeaderValue> {
        let k = name.to_lowercase();
        let header = self.keys.iter().find(|x| x.name_lower() == k)?;
        Some(header.value())
    }

    pub fn get_mut(&mut self, name: &str) -> Option<&mut HeaderValue> {
        let k = name.to_lowercase();
        let header = self.keys.iter_mut().find(|x| x.name_lower() == k)?;
        Some(header.value_mut())
    }

    pub fn remove(&mut self, name: impl AsRef<str>) -> Option<HeaderValue> {
        let lower = name.as_ref().to_lowercase();
        let pos = self.keys.iter().position(|x| x.name_lower() == lower)?;
        Some(self.keys.remove(pos).into_value())
    }

    pub fn as_h2c(&self) -> HlsResult<Vec<HeaderKey>> {
        let mut res = self.keys.clone();
        res.insert(0, HeaderKey::new(":method", HeaderValue::String(self.method.to_string())));
        let invalid_keys = ["connection", "host", "content-length", "transfer-encoding", "upgrade"];
        let res = res.into_iter().filter(|x| !invalid_keys.contains(&x.name_lower().as_str()) && x.value().to_string() != "").collect();
        Ok(res)
    }

    pub fn add_cookie(&mut self, cookie: Cookie) {
        match self.keys.iter_mut().find(|x| x.name_lower() == "cookie") {
            None => self.keys.push(HeaderKey::new("cookie", HeaderValue::Cookies(vec![cookie]))),
            Some(header) => header.value_mut().add_cookie(cookie)
        }
    }

    pub fn set_cookies(&mut self, ck: Vec<Cookie>) {
        let header = self.keys.iter_mut().find(|x| x.name_lower() == "cookie");
        match header {
            None => self.keys.push(HeaderKey::new("cookie", HeaderValue::Cookies(ck))),
            Some(header) => header.set_value(HeaderValue::Cookies(ck))
        }
    }

    pub fn set_cookie(&mut self, ck: impl AsRef<str>) -> HlsResult<()> {
        let cookies = Cookie::from_req(ck.as_ref())?;
        self.set_cookies(cookies);
        Ok(())
    }

    ///cookie请使用set_cookie/add_cookie
    pub fn insert(&mut self, k: impl AsRef<str>, v: impl ToString) -> HlsResult<()> {
        let lower_key = k.as_ref().to_lowercase().replace("contentlength", "content-length")
            .replace("contenttype", "content-type");
        let header = self.keys.iter_mut().find(|x| x.name_lower() == lower_key);
        if let Some(header) = header {
            match header.name_lower().as_str() {
                "cookie" => {
                    let mut cookies = Cookie::from_req(v.to_string())?;
                    match cookies.len() {
                        2.. => header.set_value(HeaderValue::Cookies(cookies)),
                        1 => header.value_mut().add_cookie(cookies.remove(0)),
                        0 => {}
                    }
                }
                "content-length" => header.set_value(HeaderValue::Number(v.to_string().parse()?)),
                "content-type" => header.set_value(HeaderValue::ContextType(ContentType::try_from(&v.to_string())?)),
                "upgrade-insecure-requests" => header.set_value(HeaderValue::Bool(v.to_string() == "1")),
                "set-cookie" => header.value_mut().add_cookie(Cookie::from_res(v.to_string())?),
                _ => header.set_value(HeaderValue::String(v.to_string())),
            }
        } else {
            match lower_key.as_ref() {
                "set-cookie" => {
                    let cookie = Cookie::from_res(v.to_string())?;
                    self.keys.push(HeaderKey::new(k.as_ref(), HeaderValue::Cookies(vec![cookie])));
                }
                "cookie" => {
                    let cookies = Cookie::from_req(v.to_string())?;
                    self.keys.push(HeaderKey::new(k.as_ref(), HeaderValue::Cookies(cookies)));
                }
                "content-length" => self.keys.push(HeaderKey::new(k.as_ref(), HeaderValue::Number(v.to_string().parse()?))),
                "content-type" => self.keys.push(HeaderKey::new(k.as_ref(), HeaderValue::ContextType(ContentType::try_from(&v.to_string())?))),
                _ => self.keys.push(HeaderKey::new(k.as_ref(), HeaderValue::String(v.to_string()))),
            }
        }
        Ok(())
    }

    pub fn set_user_agent(&mut self, user_agent: impl ToString) -> HlsResult<()> {
        self.insert("user-agent", user_agent)
    }

    pub fn set_sec_ch_ua(&mut self, sec_ch_ua: impl ToString) -> HlsResult<()> {
        self.insert("sec-ch-ua", sec_ch_ua.to_string())
    }


    pub fn set_sec_ch_ua_mobile(&mut self, sec_ch_ua_mobile: impl ToString) -> HlsResult<()> {
        self.insert("sec-ch-ua-mobile", sec_ch_ua_mobile.to_string())
    }


    pub fn set_sec_ch_ua_platform(&mut self, sec_ch_ua_platform: impl ToString) -> HlsResult<()> {
        self.insert("sec-ch-ua-platform", sec_ch_ua_platform.to_string())
    }


    pub fn user_agent(&self) -> Option<&str> {
        self.get("user-agent")?.as_string()
    }

    pub fn set_host(&mut self, host: impl ToString) -> HlsResult<()> {
        self.insert("host", host)
    }

    pub fn host(&self) -> Option<&str> {
        self.get("host")?.as_string()
    }

    pub fn set_origin(&mut self, origin: impl ToString) -> HlsResult<()> {
        self.insert("origin", origin)
    }

    pub fn set_referer(&mut self, referer: impl ToString) -> HlsResult<()> {
        self.insert("referer", referer)
    }

    pub fn set_accept(&mut self, accept: impl ToString) -> HlsResult<()> {
        self.insert("accept", accept)
    }

    pub fn set_content_length(&mut self, content_length: usize) -> HlsResult<()> {
        self.insert("content-length", content_length)
    }

    pub fn set_content_type(&mut self, content_type: ContentType) {
        let header = self.keys.iter_mut().find(|x| x.name_lower() == "content-type");
        if let Some(header) = header {
            header.set_value(HeaderValue::ContextType(content_type))
        } else {
            self.keys.push(HeaderKey::new("content-type", HeaderValue::ContextType(content_type)));
        }
    }

    pub fn set_connection(&mut self, connection: impl ToString) -> HlsResult<()> {
        self.insert("connection", connection)
    }

    pub fn content_length(&self) -> Option<usize> {
        let value = self.get("content-length")?;
        match value {
            HeaderValue::Number(len) => Some(*len),
            _ => None
        }
    }

    pub fn content_type(&self) -> Option<&ContentType> {
        match self.get("content-type")? {
            HeaderValue::ContextType(ct) => Some(ct),
            _ => None
        }
    }

    pub fn cookies(&self) -> Option<&Vec<Cookie>> {
        let header = self.keys.iter().find(|x| x.name_lower() == "cookie" || x.name_lower() == "set-cookie");
        header?.cookies()
    }

    pub fn method(&self) -> &Method { &self.method }

    pub fn alpn(&self) -> &ALPN { &self.alpn }

    pub fn uri(&self) -> &Uri {
        &self.uri
    }

    pub fn uri_mut(&mut self) -> &mut Uri { &mut self.uri }

    pub fn is_empty(&self) -> bool {
        self.alpn.value().is_empty()
    }

    pub fn content_encoding(&self) -> Option<&str> {
        self.get("content-encoding")?.as_string()
    }

    pub fn set_content_encoding(&mut self, encoding: impl ToString) -> HlsResult<()> {
        self.insert("content-encoding", encoding)
    }

    pub fn accept_encoding(&self) -> Option<&str> {
        self.get("accept-encoding")?.as_string()
    }

    pub fn set_method(&mut self, method: Method) { self.method = method; }

    pub fn set_uri(&mut self, uri: Uri) {
        self.uri = uri;
    }

    pub fn location(&self) -> Option<&str> {
        self.get("location")?.as_string()
    }

    pub fn authorization(&self) -> Option<&str> {
        self.get("authorization")?.as_string()
    }

    pub fn set_authorization(&mut self, authorization: impl ToString) -> HlsResult<()> {
        self.insert("authorization", authorization)
    }

    fn parse_req(value: &str) -> HlsResult<Header> {
        let mut header = Header::new_res();
        let value = value.replace("\r\n", "\n");
        for (index, line) in value.split("\n").enumerate() {
            if line.is_empty() { continue; }
            if index == 0 {
                let mut items = line.split(" ");
                header.method = Method::try_from(items.next().unwrap_or("GET")).unwrap_or(Method::GET);
                header.set_uri(Uri::try_from(items.next().unwrap_or(""))?);
                header.alpn = ALPN::from_slice(items.collect::<Vec<_>>().join(" ").to_lowercase().as_bytes());
                continue;
            }
            let mut items = line.split(": ");
            let name = items.next().unwrap_or("");
            let v = items.collect::<Vec<_>>().join(": ");
            header.insert(name, v)?;
        }
        Ok(header)
    }

    fn parse_res(value: &str) -> HlsResult<Header> {
        let mut header = Header::new_res();
        let value = value.replace("\r\n", "\n");
        for (index, line) in value.split("\n").enumerate() {
            if line.is_empty() { continue; }
            if index == 0 {
                let mut items = line.split(" ");
                header.alpn = ALPN::from_slice(items.next().unwrap_or("").to_lowercase().as_bytes());
                let status = items.next().unwrap_or("100").parse().unwrap_or(100);
                header.status = HttpStatus::new(status);
                continue;
            }
            let mut items = line.split(": ");
            let name = items.next().unwrap_or("");
            let v = items.collect::<Vec<_>>().join(": ");
            header.insert(name, v)?;
        }
        Ok(header)
    }

    pub fn parse_h2(packs: Vec<HPack>) -> HlsResult<Header> {
        let mut header = Header::new_res();
        header.alpn = ALPN::Http20;
        for pack in packs {
            header.insert(pack.name(), pack.value())?;
            match pack.name() {
                ":method" => header.method = Method::try_from(pack.value().to_uppercase())?,
                ":path" => header.uri = Uri::try_from(pack.value())?,
                ":status" => header.status = HttpStatus::new(pack.value().parse::<u16>()?),
                _ => {}
            }
        }
        Ok(header)
    }

    pub fn status(&self) -> &HttpStatus {
        &self.status
    }

    pub fn keys(&self) -> &Vec<HeaderKey> { &self.keys }

    pub(crate) fn init_by_alpn(&mut self, alpn: ALPN) {
        if alpn == self.alpn { return; }
        self.alpn = alpn;
        let keys = if let ALPN::Http20 = self.alpn { Header::new_req_h2().keys } else { Header::new_req_h1().keys };
        let keys = mem::replace(&mut self.keys, keys);
        for ok in keys {
            let nk = self.keys.iter_mut().find(|x| x.name_lower() == ok.name_lower());
            match nk {
                None => self.keys.push(ok),
                Some(nk) => nk.set_value(ok.take_value())
            }
        }
    }

    pub fn set_by_json(&mut self, headers: JsonValue) -> HlsResult<()> {
        for (k, v) in headers.entries() {
            match k.to_lowercase().as_str() {
                "cookie" => self.set_cookie(v.dump())?,
                _ => self.insert(k, v.dump())?
            }
        }
        Ok(())
    }

    pub(crate) fn hpack_coder(&mut self) -> &mut HPackCoding { &mut self.hpack_coder }
}

#[cfg(feature = "export")]
impl From<&Header> for JsonValue {
    fn from(value: &Header) -> Self {
        let mut header = crate::json::object! {
            "uri":value.uri.to_string(),
            "method":value.method.to_string(),
            "status":value.status.code(),
            "agreement":value.alpn.to_string(),
            "keys":{}
        };
        for key in &value.keys {
            let value = match key.value() {
                HeaderValue::Cookies(v) => JsonValue::from(v.clone()),
                _ => JsonValue::String(key.value().to_string())
            };
            let _ = header["keys"].insert(key.name(), value);
        }
        header
    }
}

impl TryFrom<String> for Header {
    type Error = HlsError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Header::try_from(value.as_str())
    }
}

impl TryFrom<&str> for Header {
    type Error = HlsError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.to_uppercase().starts_with("HTTP/1") {
            true => Header::parse_res(value),
            false => Header::parse_req(value),
        }
    }
}

impl Display for Header {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let raw = match self.status {
            HttpStatus::None => {
                let mut raw = self.raw(false);
                if matches!(self.alpn,ALPN::Http11|ALPN::Http10) { raw.insert(0, format!("{} {} {}", self.method, self.uri, self.alpn)); }
                raw
            }
            _ => {
                if matches!(self.alpn,ALPN::Http11|ALPN::Http10) {
                    let mut raw = self.raw(false);
                    raw.insert(0, format!("{} {} {}", self.alpn, self.status.code(), self.status.spec()));
                    raw.push("".to_string());
                    raw.push("".to_string());
                    raw
                } else {
                    let mut raw = vec![];
                    self.keys.iter().for_each(|k| match k.value() {
                        HeaderValue::Cookies(cookies) => for cookie in cookies {
                            raw.push(format!("{}: {}", k.name(), cookie.as_res()));
                        },
                        _ => raw.push(format!("{}: {}", k.name(), k.value()))
                    });
                    raw
                }
            }
        };
        f.write_str(&raw.join("\r\n"))
    }
}