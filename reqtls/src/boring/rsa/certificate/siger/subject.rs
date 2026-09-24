pub enum DnType {
    //国家，只能两个字节
    Country,
    StateOrProvince,
    Locality,
    Organization,
    OrganizationalUnit,
    Common,
}

impl DnType {
    pub const fn filed_value(&self) -> &'static str {
        match self {
            DnType::Country => "C",
            DnType::StateOrProvince => "ST",
            DnType::Locality => "L",
            DnType::Organization => "O",
            DnType::OrganizationalUnit => "OU",
            DnType::Common => "CN"
        }
    }
}