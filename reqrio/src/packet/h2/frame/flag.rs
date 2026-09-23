use std::ops::{BitOr, BitOrAssign};
#[derive(Clone, Debug, Default)]
pub struct H2FrameFlag(u8);


#[allow(non_upper_case_globals)]
impl H2FrameFlag {
    pub const Priority: H2FrameFlag = H2FrameFlag(0b0010_0000);
    pub const Padding: H2FrameFlag = H2FrameFlag(0b0000_1000);
    pub const EndHeader: H2FrameFlag = H2FrameFlag(0b0000_0100);
    pub const EndStream: H2FrameFlag = H2FrameFlag(0b0000_0001);
}

impl H2FrameFlag {
    pub fn from_u8(byte: u8) -> H2FrameFlag {
        H2FrameFlag(byte)
    }

    pub fn into_inner(self) -> u8 {
        self.0
    }

    pub fn priority(&self) -> bool {
        self.0 & H2FrameFlag::Priority.0 == 0b0010_0000
    }

    pub fn padding(&self) -> bool {
        self.0 & H2FrameFlag::Padding.0 == 0b0000_1000
    }

    pub fn end_header(&self) -> bool {
        self.0 & H2FrameFlag::EndHeader.0 == 0b0000_0100
    }

    pub fn end_stream(&self) -> bool {
        self.0 & H2FrameFlag::EndStream.0 == 0b0000_0001
    }

    pub fn inner(&self) -> u8 { self.0 }
}

impl BitOrAssign for H2FrameFlag {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl BitOr for H2FrameFlag {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        H2FrameFlag(self.0 | rhs.0)
    }
}