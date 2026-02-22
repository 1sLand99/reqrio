pub enum BasicConstraint {
    Critical,
    Ca(bool),
}

impl BasicConstraint {
    pub(crate) fn value(&self) -> String {
        match self {
            BasicConstraint::Critical => "critical".to_string(),
            BasicConstraint::Ca(v) => format!("CA:{}", if *v { "TRUE" } else { "FALSE" }),
        }
    }
}