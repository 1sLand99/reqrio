use std::ops::BitOrAssign;
#[derive(Clone, Debug)]
pub struct FrameFlag(u8);

#[allow(non_upper_case_globals)]
impl FrameFlag {
    pub const Priority: FrameFlag = FrameFlag(0b0010_0000);
    pub const Padding: FrameFlag = FrameFlag(0b0000_1000);
    pub const EndHeader: FrameFlag = FrameFlag(0b0000_0100);
    pub const EndStream: FrameFlag = FrameFlag(0b0000_0001);
}

impl FrameFlag {
    pub fn from_u8(byte: u8) -> FrameFlag {
        FrameFlag(byte)
    }

    pub fn into_inner(self) -> u8 {
        self.0
    }

    pub fn priority(&self) -> bool {
        self.0 & FrameFlag::Priority.0 == 0b0010_0000
    }

    pub fn padding(&self) -> bool {
        self.0 & FrameFlag::Padding.0 == 0b0000_1000
    }

    pub fn end_header(&self) -> bool {
        self.0 & FrameFlag::EndHeader.0 == 0b0000_0100
    }

    pub fn end_stream(&self) -> bool {
        self.0 & FrameFlag::EndStream.0 == 0b0000_0001
    }
}

impl BitOrAssign for FrameFlag {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl Default for FrameFlag {
    fn default() -> Self {
        FrameFlag(0b0000_0000)
    }
}