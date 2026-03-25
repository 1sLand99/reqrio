use super::content_type::ContentType;
use super::cookie::Cookie;
use crate::error::{HlsError, HlsResult};
use crate::hpack::{HPackItem, HPackEncode};
use crate::json::JsonValue;
use crate::reader::{ReadExt, Reader, RefReader, StrCow};
use crate::*;
pub use key::HeaderKey;
pub use method::Method;
pub use status::HttpStatus;
use std::fmt::Display;
use std::mem;
pub use value::HeaderValue;
use crate::cookie::CookieManager;

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
}

impl Header {
    pub fn new_res() -> Self {
        Self {
            method: Method::GET,
            alpn: ALPN::Custom(vec![]),
            uri: Uri::default(),
            status: HttpStatus::None,
            keys: vec![],
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
            HeaderKey::new("cookie", HeaderValue::Cookies(CookieManager::new(vec![]))),
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
            HeaderKey::new("Cookie", HeaderValue::Cookies(CookieManager::new(vec![]))),
            HeaderKey::new("Origin", HeaderValue::String("".to_string())),
            // HeaderKey::new("pragma", HeaderValue::String("".to_string())),

        ];
        res
    }

    pub fn to_req_cookie_str(&self) -> String {
        let header = self.keys.iter().find(|x| x.name().eq_ignore_ascii_case("cookie"));
        if let Some(header) = header && let Some(cookie) = header.cookies() {
            cookie.iter().map(|cookie| cookie.as_req()).collect::<Vec<_>>().join("; ")
        } else {
            "".to_string()
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

    pub fn get(&self, name: impl AsRef<str>) -> Option<&HeaderValue> {
        let header = self.keys.iter().find(|x| x.name().eq_ignore_ascii_case(name.as_ref()))?;
        Some(header.value())
    }

    pub fn get_mut(&mut self, name: impl AsRef<str>) -> Option<&mut HeaderValue> {
        let header = self.keys.iter_mut().find(|x| x.name().eq_ignore_ascii_case(name.as_ref()))?;
        Some(header.value_mut())
    }

    pub fn remove(&mut self, name: impl AsRef<str>) -> Option<HeaderValue> {
        let pos = self.keys.iter().position(|x| x.name().eq_ignore_ascii_case(name.as_ref()))?;
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
        match self.keys.iter_mut().find(|x| x.name().eq_ignore_ascii_case("cookie")) {
            None => self.keys.push(HeaderKey::new("cookie", HeaderValue::Cookies(CookieManager::new(vec![cookie])))),
            Some(header) => header.value_mut().add_cookie(cookie)
        }
    }

    pub fn set_cookies(&mut self, ck: Vec<Cookie>) {
        let header = self.keys.iter_mut().find(|x| x.name().eq_ignore_ascii_case("cookie"));
        match header {
            None => self.keys.push(HeaderKey::new("cookie", HeaderValue::Cookies(CookieManager::new(ck)))),
            Some(header) => header.set_value(HeaderValue::Cookies(CookieManager::new(ck))),
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
        let header = self.keys.iter_mut().find(|x| x.name().eq_ignore_ascii_case(&lower_key));
        if let Some(header) = header {
            match header.name_lower().as_str() {
                "cookie" => {
                    let mut cookies = Cookie::from_req(v.to_string())?;
                    match cookies.len() {
                        2.. => header.set_value(HeaderValue::Cookies(CookieManager::new(cookies))),
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
                    self.keys.push(HeaderKey::new(k.as_ref(), HeaderValue::Cookies(CookieManager::new(vec![cookie]))));
                }
                "cookie" => {
                    let cookies = Cookie::from_req(v.to_string())?;
                    self.keys.push(HeaderKey::new(k.as_ref(), HeaderValue::Cookies(CookieManager::new(cookies))));
                }
                "content-length" => self.keys.push(HeaderKey::new(k.as_ref(), HeaderValue::Number(v.to_string().parse()?))),
                "content-type" => self.keys.push(HeaderKey::new(k.as_ref(), HeaderValue::ContextType(ContentType::try_from(&v.to_string())?))),
                "update-table-size" => self.keys.push(HeaderKey::new(k.as_ref(), HeaderValue::Number(v.to_string().parse()?))),
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

    pub fn max_table_size(&self) -> Option<usize> {
        if let HeaderValue::Number(size) = self.get("update-table-size")? {
            Some(*size)
        } else { None }
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

    pub fn push_pack_item(&mut self, item: &HPackItem) -> HlsResult<()> {
        self.insert(item.name(), item.value())?;
        match item.name() {
            ":method" => self.method = Method::try_from(item.value().to_uppercase())?,
            ":path" => self.uri = Uri::try_from(item.value())?,
            ":status" => self.status = HttpStatus::new(item.value().parse::<u16>()?),
            _ => {}
        }
        Ok(())
    }

    pub fn parse_h2(packs: Vec<HPackItem>) -> HlsResult<Header> {
        let mut header = Header::new_res();
        header.alpn = ALPN::Http20;
        for pack in packs {
            header.push_pack_item(&pack)?
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

    fn as_h1_reader<'a>(&'a self, param: HeaderParam<'a>) -> H1HeaderReader<'a> {
        let mut reader = RefReader::default();
        reader.add_str(self.method.spec());
        reader.add_str(" ");
        reader.add_str(self.uri.path());
        if !self.uri.params().is_empty() { reader.add_str("?") };
        for (i, param) in self.uri.params().iter().enumerate() {
            reader.add_str(param.name());
            reader.add_str("=");
            reader.add_str(param.value_raw());
            if i != self.uri.params().len() - 1 { reader.add_str("&") }
        }
        reader.add_str(" ");
        reader.add_str("HTTP/1.1");
        reader.add_str("\r\n");
        for key in self.keys.iter() {
            if HeaderReader::skip_h1_key(key, &param.body_len) { continue; }
            reader.add_str(key.name());
            reader.add_str(": ");
            match key.name() {
                "host" | "Host" => {
                    reader.add_str(param.addr.host());
                    if param.addr.port() != 80 && param.addr.port() != 443 {
                        reader.add_str(":");
                        reader.add_string(param.addr.port().to_string());
                    }
                }
                "content-length" | "Content-Length" => reader.add_string(param.body_len.to_string()),
                "cookie" | "Cookie" => {
                    if let Some(cookies) = key.cookies() {
                        for (index, cookie) in cookies.iter().enumerate() {
                            reader.add_str(cookie.name());
                            reader.add_str("=");
                            reader.add_str(cookie.value());
                            if index != key.cookies().unwrap_or(&vec![]).len() - 1 { reader.add_str("; ") }
                        }
                    }
                }
                _ => match key.value().as_string() {
                    None => reader.add_string(key.value().to_string()),
                    Some(v) => reader.add_str(v),
                }
            }
            reader.add_str("\r\n");
        }
        reader.add_str("\r\n");
        H1HeaderReader {
            reader,
            pos: 0,
            wrote: false,
        }
    }

    fn as_h2_reader<'a>(&'a self, param: HeaderParam<'a>) -> H2HeaderReader<'a> {
        let mut keys = vec![];
        let uri = self.uri.to_string();
        keys.push((StrCow::Borrowed(":method"), StrCow::Borrowed(self.method.spec())));
        keys.push((StrCow::Borrowed(":authority"), StrCow::Borrowed(param.addr.host())));
        keys.push((StrCow::Borrowed(":scheme"), StrCow::Borrowed(param.scheme.spec())));
        let invalid_keys = ["connection", "host", "content-length", "transfer-encoding", "upgrade"];
        for key in self.keys.iter() {
            if invalid_keys.contains(&key.name_lower().as_str()) || key.value().is_empty() { continue; }
            let name = key.name_lower();
            match key.value() {
                HeaderValue::Cookies(cookies) => for cookie in cookies.as_req(param.addr.host(), &uri) {
                    keys.push((StrCow::Owned(name.clone()), StrCow::Owned(cookie.as_req())));
                }
                _ => keys.push((StrCow::Owned(name), StrCow::Owned(key.value().to_string()))),
            }
        }
        keys.insert(3, (StrCow::Borrowed(":path"), StrCow::Owned(self.uri.to_string())));
        H2HeaderReader {
            keys,
            encoder: param.encoder,
            wrote: false,
            pos: 0,
            body_len: param.body_len,
            stream_identifier: param.stream_identifier,
        }
    }

    pub(crate) fn as_reader<'a>(&'a mut self, param: HeaderParam<'a>) -> HeaderReader2<'a> {
        match self.alpn {
            ALPN::Http20 => HeaderReader2::H2(self.as_h2_reader(param)),
            _ => HeaderReader2::H1(self.as_h1_reader(param))
        }
    }
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
                HeaderValue::Cookies(v) => JsonValue::from(v.inner().clone()),
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
                        HeaderValue::Cookies(cookies) => for cookie in cookies.inner() {
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

pub struct HeaderParam<'a> {
    pub(crate) addr: &'a Addr,
    pub(crate) scheme: &'a Scheme,
    pub(crate) encoder: &'a mut HPackEncode,
    pub(crate) stream_identifier: &'a u32,
    pub(crate) body_len: usize,
}

pub struct H1HeaderReader<'a> {
    reader: RefReader<StrCow<'a>>,
    pos: usize,
    wrote: bool,
}

impl<'a> ReadExt for H1HeaderReader<'a> {
    fn wrote(&self) -> bool {
        self.wrote
    }

    fn len(&self) -> usize {
        self.reader.len()
    }

    fn read(&mut self, buf: &mut Reader) -> HlsResult<usize> {
        let start = buf.offset().end;
        if self.pos == 0 {
            self.reader.read(buf)?;
            match self.reader.wrote() {
                true => self.pos += 1,
                false => return Ok(buf.offset().end - start)
            }
        }
        self.wrote = true;
        Ok(buf.offset().end - start)
    }
}


pub struct H2HeaderReader<'a> {
    keys: Vec<(StrCow<'a>, StrCow<'a>)>,
    encoder: &'a mut HPackEncode,
    stream_identifier: &'a u32,
    wrote: bool,
    pos: usize,
    body_len: usize,
}

impl<'a> ReadExt for H2HeaderReader<'a> {
    fn wrote(&self) -> bool {
        self.wrote
    }

    fn len(&self) -> usize {
        unreachable!()
    }

    fn read(&mut self, buf: &mut Reader) -> HlsResult<usize> {
        let len: usize = self.keys.iter().map(|(k, v)| k.len() + v.len()).sum();
        if buf.unfilled_len() < 59 + len { return Ok(0); }
        let offset = buf.offset();
        let mut header_frame = H2Frame::new_header(self.body_len, *self.stream_identifier);
        header_frame.set_priority(146);
        header_frame.write_to(buf);
        for (i, (key, value)) in self.keys.iter().enumerate() {
            if i < self.pos { continue; }
            if buf.unfilled_len() < key.len() + value.len() { return Ok(buf.offset().end - offset.end); }
            self.encoder.encode_one(key, value, buf);
            self.pos += 1;
        }
        //有priority，payload长度需要frame.len-9
        buf.write_u32_in(offset.end, (buf.offset().end - offset.end - 9) as u32, true);
        self.wrote = true;
        self.wrote = true;
        Ok(buf.offset().end - offset.end)
    }
}

pub enum HeaderReader2<'a> {
    H1(H1HeaderReader<'a>),
    H2(H2HeaderReader<'a>),
}

impl<'a> ReadExt for HeaderReader2<'a> {
    fn wrote(&self) -> bool {
        match self {
            HeaderReader2::H1(h1) => h1.wrote(),
            HeaderReader2::H2(h2) => h2.wrote(),
        }
    }

    fn len(&self) -> usize {
        match self {
            HeaderReader2::H1(h1) => h1.len(),
            HeaderReader2::H2(h2) => h2.len(),
        }
    }

    fn read(&mut self, buf: &mut Reader) -> HlsResult<usize> {
        match self {
            HeaderReader2::H1(h1) => h1.read(buf),
            HeaderReader2::H2(h2) => h2.read(buf),
        }
    }
}


pub struct HeaderReader<'a> {
    header: &'a Header,
    addr: &'a Addr,
    scheme: &'a Scheme,
    stream_identifier: &'a u32,
    hpack_encoder: &'a mut HPackEncode,
    body_len: usize,
    pos: usize,
    wrote: bool,
}

impl<'a> HeaderReader<'a> {
    fn skip_h1_key(key: &HeaderKey, body_len: &usize) -> bool {
        let is_ctx_len = key.name().eq_ignore_ascii_case("content-length");
        if is_ctx_len && body_len != &0 { return false; }
        let is_host = key.name().eq_ignore_ascii_case("host");
        if is_host { return false; }
        key.value().is_empty()
    }

    pub fn read_h1(&mut self, buf: &mut Reader) -> HlsResult<usize> {
        let start = buf.offset().end;
        // first line: Method uri version
        if self.pos == 0 {
            if buf.unfilled_len() < self.header.uri.len() * 2 { return Ok(buf.offset().end - start); }
            buf.write_slice(self.header.method.to_string().as_bytes());
            buf.write_u8(b' ');
            buf.write_slice(self.header.uri.to_string().as_bytes());
            buf.write_u8(b' ');
            buf.write_slice(self.header.alpn.to_string().as_bytes());
            buf.write_slice(b"\r\n");
            self.pos += 1;
        }
        let mut index = 1;
        //header keys
        for key in self.header.keys.iter() {
            if Self::skip_h1_key(key, &self.body_len) { continue; }
            if index < self.pos {
                index += 1;
                continue;
            }
            let len = key.name().len() + key.value().may_len() + self.addr.host().len() + 4;
            // println!("{} {} {} {}", key.name(), buf.capacity(), buf.len(), len);
            if buf.unfilled_len() < len { return Ok(buf.offset().end - start); }
            buf.write_slice(key.name().as_bytes());
            buf.write_slice(b": ");
            match key.name_lower().as_str() {
                "host" => {
                    buf.write_slice(self.addr.host().as_bytes());
                    if self.addr.port() != 80 && self.addr.port() != 443 {
                        buf.write_slice(b":");
                        buf.write_slice(self.addr.port().to_string().as_bytes());
                    }
                }
                "content-length" => buf.write_slice(self.body_len.to_string().as_bytes()),
                "cookie" => {
                    for (index, cookie) in key.cookies().unwrap_or(&vec![]).iter().enumerate() {
                        buf.write_slice(cookie.name().as_bytes());
                        buf.write_u8(b'=');
                        buf.write_slice(cookie.value().as_bytes());
                        if index != key.cookies().unwrap_or(&vec![]).len() - 1 { buf.write_slice(b"; ") }
                    }
                }
                _ => buf.write_slice(key.value().as_string().unwrap_or(&key.value().to_string()).as_bytes()),
            }
            buf.write_slice(b"\r\n");
            index += 1;
            self.pos += 1;
        }
        if buf.unfilled_len() < 2 { return Ok(buf.offset().end - start); }
        buf.write_slice(b"\r\n");
        self.wrote = true;
        Ok(buf.offset().end - start)
    }

    pub fn read_h2(&mut self, buf: &mut Reader) -> HlsResult<usize> {
        let len = 59 + self.addr.host().len() + self.header.uri.len();
        let invalid_keys = ["connection", "host", "content-length", "transfer-encoding", "upgrade"];
        let keys = self.header.keys.iter().filter(|x| !invalid_keys.contains(&x.name_lower().as_str()) && !x.value().is_empty());
        let kln: usize = keys.clone().map(|x| x.name().len() + x.value().may_len() + 10).sum();
        if buf.unfilled_len() < len + kln { return Err(BufferError::CapacityTooSmall { needed: len + kln, current: buf.capacity() }.into()); }

        let offset = buf.offset();
        let mut header_frame = H2Frame::new_header(self.body_len, *self.stream_identifier);
        header_frame.set_priority(146);
        header_frame.write_to(buf);
        let host = self.addr.to_string().replace(":80", "").replace(":443", "");
        let uri = self.header.uri.to_string();
        self.hpack_encoder.encode_one(":method", self.header.method.to_string(), buf);
        self.hpack_encoder.encode_one(":authority", &host, buf);
        self.hpack_encoder.encode_one(":scheme", self.scheme.to_string(), buf);
        self.hpack_encoder.encode_one(":path", &uri, buf);
        for key in keys {
            let name = key.name_lower();
            match key.value() {
                HeaderValue::Cookies(cookies) => for cookie in cookies.as_req(&host, &uri) {
                    self.hpack_encoder.encode_one(&name, cookie.as_req(), buf);
                }
                _ => self.hpack_encoder.encode_one(name, key.value().to_string(), buf),
            }
        }
        //有priority，payload长度需要frame.len-9
        buf.write_u32_in(offset.start, (buf.offset().end - offset.end - 9) as u32, true);
        self.wrote = true;
        Ok(buf.offset().end - offset.end)
    }

    pub fn set_body_len(&mut self, body_len: usize) {
        self.body_len = body_len;
    }
}

impl<'a> ReadExt for HeaderReader<'a> {
    fn wrote(&self) -> bool {
        self.wrote
    }

    fn len(&self) -> usize {
        unreachable!()
    }

    fn read(&mut self, buf: &mut Reader) -> HlsResult<usize> {
        match self.header.alpn {
            ALPN::Http20 => self.read_h2(buf),
            ALPN::Http11 | ALPN::Http10 => self.read_h1(buf),
            ALPN::Custom(_) => Err(HlsError::UnsupportedAlpn(self.header.alpn.clone()).into()),
        }
    }
}

