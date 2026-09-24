pub enum KeyIdentifier {
    Hash
}

impl KeyIdentifier {
    pub(crate) const fn value(&self) -> &str {
        match self { KeyIdentifier::Hash => "hash" }
    }
}