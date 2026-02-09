#[derive(Eq, PartialEq, Clone)]
pub enum Padding {
    NoPadding,
    PKCS5Padding, //block size 8,
    PKCS7Padding, //block size 1-255, ...data.len()%block size*
    ZeroPadding, //...000*
    BitPadding, //....1 000*
}

impl Padding {
    pub fn add_padding(&self, data: &mut Vec<u8>) {
        let padding_size = 16 - data.len() % 16;
        match self {
            Padding::BitPadding => {
                data.push(1);
                data.extend(vec![0; padding_size - 1]);
            }
            Padding::PKCS5Padding => {
                let padding_size = data.len() % 8;
                data.extend(vec![padding_size as u8; padding_size]);
            }
            Padding::PKCS7Padding => data.extend(vec![padding_size as u8; padding_size]),
            Padding::NoPadding => {}
            Padding::ZeroPadding => data.extend(vec![0; padding_size])
        }
    }

    pub fn remove_padding(&self, data: &mut Vec<u8>) {
        if data.is_empty() { return; }
        match self {
            Padding::BitPadding => {
                let end_bit = data[data.len() - 1];
                if end_bit < 2 {
                    while !data.ends_with(&[1]) {
                        data.remove(data.len() - 1);
                    }
                    data.remove(data.len() - 1);
                }
            }
            Padding::PKCS5Padding => {
                let end_bit = data[data.len() - 1];
                if end_bit < 8 {
                    while data.ends_with(&[end_bit]) {
                        data.remove(data.len() - 1);
                    }
                }
            }
            Padding::PKCS7Padding => {
                let end_bit = data[data.len() - 1];
                if end_bit <= 16 {
                    while data.ends_with(&[end_bit]) {
                        data.remove(data.len() - 1);
                    }
                }
            }
            Padding::NoPadding => {}
            Padding::ZeroPadding => {
                while data.ends_with(&[0]) {
                    data.remove(data.len() - 1);
                }
            }
        }
    }
}
