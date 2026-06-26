#[derive(Debug)]
pub enum HeaderError {
    MissingBasicKey(&'static str),
}