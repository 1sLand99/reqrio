use crate::boring::certificate::siger::alt_name::SubjectAltName;
use crate::boring::certificate::siger::basic_constraints::BasicConstraint;
use crate::boring::certificate::siger::key_identifier::KeyIdentifier;
use super::super::super::bindings::*;
use super::key_usage::KeyUsage;

pub enum CertExtend {
    KeyUsage(Vec<KeyUsage>),
    ExtKeyUsage(Vec<KeyUsage>),
    KeyIdentifier(Vec<KeyIdentifier>),
    BasicConstraints(Vec<BasicConstraint>),
    SubjectAltName(Vec<SubjectAltName>),
}


impl CertExtend {
    pub(crate) fn nid(&self) -> i32 {
        match self {
            CertExtend::KeyUsage(_) => NID_key_usage,
            CertExtend::ExtKeyUsage(_) => NID_ext_key_usage,
            CertExtend::KeyIdentifier(_) => NID_subject_key_identifier,
            CertExtend::BasicConstraints(_) => NID_basic_constraints,
            CertExtend::SubjectAltName(_) => NID_subject_alt_name,
        }
    }

    pub(crate) fn value(&self) -> String {
        match self {
            CertExtend::KeyUsage(usage) => usage.iter().map(|x| x.value()).collect::<Vec<_>>().join(","),
            CertExtend::ExtKeyUsage(usage) => usage.iter().map(|x| x.value()).collect::<Vec<_>>().join(","),
            CertExtend::KeyIdentifier(identifiers) => identifiers.iter().map(|x| x.value()).collect::<Vec<_>>().join(","),
            CertExtend::BasicConstraints(constraints) => constraints.iter().map(|x| x.value()).collect::<Vec<_>>().join(","),
            CertExtend::SubjectAltName(alt_name) => alt_name.iter().map(|x| x.value()).collect::<Vec<_>>().join(","),
        }
    }
}