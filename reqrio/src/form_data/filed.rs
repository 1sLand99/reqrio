pub(crate) struct FormField {
    pub(crate) name: String,
    pub(crate) value: String,
}

impl FormField {
    pub fn new(name: impl ToString, value: impl ToString) -> Self {
        FormField {
            name: name.to_string(),
            value: value.to_string(),
        }
    }
}