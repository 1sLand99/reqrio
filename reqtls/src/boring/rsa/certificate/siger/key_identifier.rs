pub enum KeyIdentifier {
    Hash
}

impl KeyIdentifier {
    pub(crate) fn value(&self) -> &str {
        match self { KeyIdentifier::Hash => "hash" }
    }
}