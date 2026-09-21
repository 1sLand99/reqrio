use crate::buffer::Buf;
use crate::NamedCurve;
#[cfg(debug_assertions)]
use std::fmt::{Debug, Formatter};
use std::ptr::null;
use std::slice;

#[repr(C)]
#[derive(Default, Clone)]
pub struct KeyEntry {
    group: u16,
    key_len: u16,
    key: *const u8,
}

impl KeyEntry {
    pub const X25519MLKEM768: KeyEntry = KeyEntry::new(NamedCurve::X25519MLKEM768);
    pub const X25519: KeyEntry = KeyEntry::new(NamedCurve::X25519);
    #[allow(non_upper_case_globals)]
    pub const SecP256r1: KeyEntry = KeyEntry::new(NamedCurve::SecP256r1);
    #[allow(non_upper_case_globals)]
    pub const SecP384r1: KeyEntry = KeyEntry::new(NamedCurve::SecP384r1);
    #[allow(non_upper_case_globals)]
    pub const SecP521r1: KeyEntry = KeyEntry::new(NamedCurve::SecP521r1);
    pub const fn new(group: NamedCurve) -> KeyEntry {
        KeyEntry {
            group: group.into_inner(),
            key_len: 0,
            key: null(),
        }
    }

    pub fn group(&self) -> NamedCurve {
        NamedCurve::new(self.group)
    }

    pub fn set_key(&mut self, key: Buf) {
        self.key_len = key.len() as u16;
        self.key = key.as_ptr();
    }

    pub fn is_empty(&self) -> bool {
        self.key.is_null()
    }

    pub fn key(&self) -> Buf<'_> {
        Buf::Ref(unsafe { slice::from_raw_parts(self.key, self.key_len as usize) })
    }
}

#[cfg(debug_assertions)]
impl Debug for KeyEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut struct_debug = f.debug_struct("KeyEntry");
        struct_debug.field("group", &NamedCurve::new(self.group));
        struct_debug.field("key_len", &self.key_len);
        struct_debug.field("key", &hex::encode(self.key()));
        struct_debug.finish()
    }
}

unsafe impl Sync for KeyEntry {}
unsafe impl Send for KeyEntry {}