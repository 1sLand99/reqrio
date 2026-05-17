use std::borrow::Cow;
use super::content_type::ContentType;
use super::cookie::Cookie;
use crate::cookie::CookieManager;
use crate::error::{HlsError, HlsResult};
use crate::hpack::HPackItem;
use crate::json::JsonValue;
use crate::reader::{RefReader, StrCow};
use crate::*;
pub use key::HeaderKey;
pub use method::Method;
pub use reader::{HeaderReader, HeaderParam};
use reader::{H1HeaderReader, H2HeaderReader};
pub use status::HttpStatus;
use std::fmt::Display;
use std::mem;
pub use value::HeaderValue;

mod value;
mod key;
mod method;
mod status;
mod reader;

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
            HeaderKey::new_reserved("cache-control", HeaderValue::String("".to_string())),
            HeaderKey::new_reserved("sec-ch-ua", HeaderValue::String("".to_string())),
            HeaderKey::new_reserved("sec-ch-ua-mobile", HeaderValue::String("".to_string())),
            HeaderKey::new_reserved("sec-ch-ua-full-version", HeaderValue::String("".to_string())),
            HeaderKey::new_reserved("sec-ch-ua-arch", HeaderValue::String("".to_string())),
            HeaderKey::new_reserved("sec-ch-ua-platform", HeaderValue::String("".to_string())),
            HeaderKey::new_reserved("sec-ch-ua-platform-version", HeaderValue::String("".to_string())),
            HeaderKey::new_reserved("sec-ch-ua-model", HeaderValue::String("".to_string())),
            HeaderKey::new_reserved("sec-ch-ua-bitness", HeaderValue::String("".to_string())),
            HeaderKey::new_reserved("sec-ch-ua-full-version-list", HeaderValue::String("".to_string())),
            HeaderKey::new_reserved("upgrade-insecure-requests", HeaderValue::Bool(true)),
            HeaderKey::new_reserved("user-agent", HeaderValue::String("".to_string())),
            HeaderKey::new_reserved("accept", HeaderValue::String("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7".to_string())),
            HeaderKey::new_reserved("origin", HeaderValue::String("".to_string())),
            HeaderKey::new_reserved("sec-fetch-site", HeaderValue::String("".to_string())),
            HeaderKey::new_reserved("sec-fetch-mode", HeaderValue::String("".to_string())),
            HeaderKey::new_reserved("sec-fetch-user", HeaderValue::String("".to_string())),
            HeaderKey::new_reserved("sec-fetch-dest", HeaderValue::String("".to_string())),
            HeaderKey::new_reserved("sec-fetch-storage-access", HeaderValue::String("".to_string())),
            HeaderKey::new_reserved("referer", HeaderValue::String("".to_string())),
            HeaderKey::new_reserved("accept-encoding", HeaderValue::String("gzip, deflate, br, zstd".to_string())),
            HeaderKey::new_reserved("accept-language", HeaderValue::String("zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6".to_string())),
            HeaderKey::new_reserved("cookie", HeaderValue::Cookies(CookieManager::new(vec![]))),
            HeaderKey::new_reserved("priority", HeaderValue::String("".to_string())),
            //unknown or http
            HeaderKey::new_reserved("content-encoding", HeaderValue::String("".to_string())),
            HeaderKey::new_reserved("content-type", HeaderValue::String("".to_string())),
            HeaderKey::new_reserved("authorization", HeaderValue::String("".to_string())),
        ];
        res
    }

    pub fn new_req_h1() -> Self {
        let mut res = Header::new_res();
        res.alpn = ALPN::Http11;
        res.keys = vec![
            HeaderKey::new_reserved("Host", HeaderValue::String("".to_string())),
            HeaderKey::new_reserved("Connection", HeaderValue::String("".to_string())),
            HeaderKey::new_reserved("Content-Length", HeaderValue::Number(0)),
            HeaderKey::new_reserved("Authorization", HeaderValue::String("".to_string())),
            HeaderKey::new_reserved("Content-Type", HeaderValue::String("".to_string())),
            HeaderKey::new_reserved("Cache-Control", HeaderValue::String("".to_string())),
            HeaderKey::new_reserved("sec-ch-ua", HeaderValue::String("".to_string())),
            HeaderKey::new_reserved("sec-ch-ua-mobile", HeaderValue::String("".to_string())),
            HeaderKey::new_reserved("sec-ch-ua-platform", HeaderValue::String("".to_string())),
            HeaderKey::new_reserved("Upgrade-Insecure-Requests", HeaderValue::Bool(true)),
            HeaderKey::new_reserved("User-Agent", HeaderValue::String("".to_string())),
            HeaderKey::new_reserved("Accept", HeaderValue::String("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7".to_string())),
            HeaderKey::new_reserved("Sec-Fetch-Site", HeaderValue::String("".to_string())),
            HeaderKey::new_reserved("Sec-Fetch-Mode", HeaderValue::String("".to_string())),
            HeaderKey::new_reserved("Sec-Fetch-User", HeaderValue::String("".to_string())),
            HeaderKey::new_reserved("Sec-Fetch-Dest", HeaderValue::String("".to_string())),
            HeaderKey::new_reserved("Sec-Fetch-Storage-Access", HeaderValue::String("".to_string())),
            HeaderKey::new_reserved("Referer", HeaderValue::String("".to_string())),
            HeaderKey::new_reserved("Accept-Encoding", HeaderValue::String("gzip, deflate, br, zstd".to_string())),
            HeaderKey::new_reserved("Accept-Language", HeaderValue::String("zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6".to_string())),
            HeaderKey::new_reserved("Cookie", HeaderValue::Cookies(CookieManager::new(vec![]))),
            HeaderKey::new_reserved("Origin", HeaderValue::String("".to_string())),

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
                "set-cookie" => for cookie in key.cookies().unwrap_or(&[]) {
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

    pub fn sec_ch_ua(&self) -> Option<&str> {
        self.get("sec-ch-ua")?.as_string()
    }

    pub fn set_sec_ch_ua_mobile(&mut self, sec_ch_ua_mobile: impl ToString) -> HlsResult<()> {
        self.insert("sec-ch-ua-mobile", sec_ch_ua_mobile.to_string())
    }

    pub fn sec_ch_ua_mobile(&self) -> Option<&str> {
        self.get("sec-ch-ua-mobile")?.as_string()
    }

    pub fn set_sec_ch_ua_platform(&mut self, sec_ch_ua_platform: impl ToString) -> HlsResult<()> {
        self.insert("sec-ch-ua-platform", sec_ch_ua_platform.to_string())
    }

    pub fn sec_ch_ua_platform(&self) -> Option<&str> {
        self.get("sec-ch-ua-platform")?.as_string()
    }

    pub fn user_agent(&self) -> Option<&str> {
        self.get("user-agent")?.as_string()
    }

    #[deprecated = "it will be auto fill by addr"]
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

    pub fn referer(&self) -> Option<&str> {
        self.get("referer")?.as_string()
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

    pub fn cookies(&self) -> Option<&[Cookie]> {
        let header = self.keys.iter().find(|x| x.name_lower() == "cookie" || x.name_lower() == "set-cookie");
        header?.cookies()
    }

    pub fn method(&self) -> &Method { &self.method }

    pub fn alpn(&self) -> &ALPN { &self.alpn }

    pub fn uri(&self) -> &Uri {
        &self.uri
    }

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

    fn as_h1_reader<'a>(&'a self, params: HeaderParam<'a>, ct: &'a ContentType) -> H1HeaderReader<'a> {
        let mut reader = RefReader::default();
        reader.add_str(self.method.spec());
        reader.add_str(" ");
        if params.url.uri().is_empty() {
            reader.add_str("/")
        } else {
            reader.add_str(params.url.uri().path());
        }
        if !params.url.uri().params().is_empty() { reader.add_str("?") };
        for (i, param) in params.url.uri().params().iter().enumerate() {
            reader.add_str(param.name());
            reader.add_str("=");
            reader.add_str(param.value_raw());
            if i != params.url.uri().params().len() - 1 { reader.add_str("&") }
        }
        reader.add_str(" ");
        reader.add_str("HTTP/1.1");
        reader.add_str("\r\n");
        for key in self.keys.iter() {
            if H1HeaderReader::skip_h1_key(key, &params.body_len, ct) { continue; }
            reader.add_str(key.name());
            reader.add_str(": ");
            match key.name() {
                "host" | "Host" => {
                    reader.add_str(params.url.sni());
                    if params.url.addr().port() != 80 && params.url.addr().port() != 443 {
                        reader.add_str(":");
                        reader.add_string(params.url.addr().port().to_string());
                    }
                }
                "content-length" | "Content-Length" => reader.add_string(params.body_len.to_string()),
                "content-type" | "Content-Type" => match ct.spec() {
                    Cow::Borrowed(b) => reader.add_str(b),
                    Cow::Owned(o) => reader.add_string(o),
                }
                "cookie" | "Cookie" => {
                    if let Some(cookies) = key.cookies() {
                        for (index, cookie) in cookies.iter().enumerate() {
                            reader.add_str(cookie.name());
                            reader.add_str("=");
                            reader.add_str(cookie.value());
                            if index != key.cookies().unwrap_or(&[]).len() - 1 { reader.add_str("; ") }
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

    fn as_h2_reader<'a>(&'a self, param: HeaderParam<'a>, ct: &'a ContentType) -> H2HeaderReader<'a> {
        let mut keys = vec![];
        let uri = if param.url.uri().is_empty() { StrCow::Borrowed("/") } else { StrCow::Owned(param.url.uri().to_string()) };
        keys.push((StrCow::Borrowed(":method"), StrCow::Borrowed(self.method.spec())));
        if param.url.addr().port() == 443 || param.url.addr().port() == 80 {
            keys.push((StrCow::Borrowed(":authority"), StrCow::Borrowed(param.url.sni())));
        } else {
            keys.push((StrCow::Borrowed(":authority"), StrCow::Owned(format!("{}:{}", param.url.sni(), param.url.addr().port()))));
        }
        keys.push((StrCow::Borrowed(":scheme"), StrCow::Borrowed(param.url.scheme().spec())));
        // println!("{}", self);
        for key in self.keys.iter() {
            if H2HeaderReader::skip_h2_key(key, ct) { continue; }
            let name = key.name_lower();
            if name == "content-type" {
                match ct.spec() {
                    Cow::Borrowed(b) => keys.push((StrCow::Owned(name), StrCow::Borrowed(b))),
                    Cow::Owned(o) => keys.push((StrCow::Owned(name), StrCow::Owned(o))),
                }
                continue;
            }
            match key.value() {
                HeaderValue::Cookies(cookies) => for cookie in cookies.as_req(param.url.sni(), uri.as_ref()) {
                    keys.push((StrCow::Owned(name.clone()), StrCow::Owned(cookie.as_req())));
                }
                _ => keys.push((StrCow::Owned(name), StrCow::Owned(key.value().to_string()))),
            }
        }
        keys.insert(3, (StrCow::Borrowed(":path"), uri));
        H2HeaderReader {
            keys,
            encoder: param.encoder,
            wrote: false,
            pos: 0,
            body_len: param.body_len,
            stream_identifier: param.stream_identifier,
            weight: param.weight,
            priority: param.priority,
        }
    }

    pub(crate) fn as_reader<'a>(&'a mut self, param: HeaderParam<'a>, ct: &'a ContentType) -> HeaderReader<'a> {
        match self.alpn {
            ALPN::Http20 => HeaderReader::H2(self.as_h2_reader(param, ct)),
            _ => HeaderReader::H1(self.as_h1_reader(param, ct))
        }
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





