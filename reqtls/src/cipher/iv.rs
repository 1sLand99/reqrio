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

    pub fn as_array(&self, seq: u64) -> Vec<u8> {
        let mut buf = vec![0; 16];
        match self.fix_iv.len() {
            4 => {
                buf[0..4].copy_from_slice(&self.fix_iv);
                buf[4..12].copy_from_slice(&self.explicit);
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

    pub fn decrypting_iv(&self) -> Vec<u8> {
        match self.fix_iv.len() {
            12 => self.fix_iv.clone(),
            16 => self.explicit.clone(),
            _ => [self.fix_iv.as_slice(), self.explicit.as_slice()].concat()
        }
    }

    pub fn set_explicit(&mut self, explicit: Vec<u8>) {
        self.explicit = explicit;
    }
}