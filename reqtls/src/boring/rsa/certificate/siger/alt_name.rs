pub enum SubjectAltName {
    DNS(String)
}

impl SubjectAltName {
    pub fn dns(dns: impl ToString) -> SubjectAltName {
        SubjectAltName::DNS(dns.to_string())
    }
    pub(crate) fn value(&self) -> String {
        match self { SubjectAltName::DNS(domain) => format!("DNS:{}", domain) }
    }
}