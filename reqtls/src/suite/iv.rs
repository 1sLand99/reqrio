use std::borrow::Cow;

#[derive(Debug)]
pub struct Iv {
    fix_iv: Vec<u8>,
    explicit: Vec<u8>,
}

impl Iv {
    pub fn new(fix_iv: &[u8], explicit: Vec<u8>) -> Iv {
        Iv {
            fix_iv: fix_iv.to_vec(),
            explicit: explicit.to_vec(),
        }
    }

    pub fn as_array(&self, seq: u64, explicit: Option<&[u8]>) -> Vec<u8> {
        let mut buf = vec![0; 16];
        match self.fix_iv.len() {
            4 => {
                buf[0..4].copy_from_slice(&self.fix_iv);
                if let Some(explicit) = explicit {
                    buf[4..12].copy_from_slice(explicit);
                } else {
                    buf[4..12].copy_from_slice(&self.explicit);
                }
            }
            12 => buf[0..12].copy_from_slice(&self.fix_iv),
            16 => return self.fix_iv.clone(),
            _ => panic!("invalid fix iv length")
        }

        let sbs = seq.to_be_bytes();
        for (i, b) in buf[4..12].iter_mut().enumerate() {
            *b ^= sbs[i];
        }
        buf.truncate(12);
        buf
    }

    pub fn decrypting_iv<'a>(&'a self, explicit: Option<&'a [u8]>) -> Cow<'a, [u8]> {
        let explicit = match explicit {
            Some(explicit) => explicit,
            None => &self.explicit
        };
        match self.fix_iv.len() {
            12 => Cow::Borrowed(&self.fix_iv),
            16 => Cow::Borrowed(explicit),
            _ => Cow::Owned([self.fix_iv.as_slice(), explicit].concat())
        }
    }
}