use std::fmt::{Debug, Display};

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct H2FrameType(u8);

#[allow(non_upper_case_globals)]
impl H2FrameType {
    pub const Data: H2FrameType = H2FrameType::new(0x00);
    pub const Headers: H2FrameType = H2FrameType::new(0x01);
    pub const Priority: H2FrameType = H2FrameType::new(0x02);
    pub const RstStream: H2FrameType = H2FrameType::new(0x03);
    pub const Settings: H2FrameType = H2FrameType::new(0x04);
    pub const PushPromise: H2FrameType = H2FrameType::new(0x05);
    pub const Ping: H2FrameType = H2FrameType::new(0x06);
    pub const Goaway: H2FrameType = H2FrameType::new(0x07);
    pub const WindowUpdate: H2FrameType = H2FrameType::new(0x08);
    pub const Continuation: H2FrameType = H2FrameType::new(0x09);
}


impl H2FrameType {
    pub const fn new(val: u8) -> H2FrameType {
        H2FrameType(val)
    }
    pub const fn into_inner(self) -> u8 { self.0 }

    pub const fn inner(&self) -> u8 { self.0 }
}

impl Debug for H2FrameType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}


impl Display for H2FrameType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            H2FrameType::Data => write!(f, "Data(0x({:02x}))", self.0),
            H2FrameType::Headers => write!(f, "Headers(0x({:02x}))", self.0),
            H2FrameType::Priority => write!(f, "Priority(0x({:02x}))", self.0),
            H2FrameType::RstStream => write!(f, "RstStream(0x({:02x}))", self.0),
            H2FrameType::Settings => write!(f, "Settings(0x({:02x}))", self.0),
            H2FrameType::PushPromise => write!(f, "PushPromise(0x({:02x}))", self.0),
            H2FrameType::Ping => write!(f, "Ping(0x({:02x}))", self.0),
            H2FrameType::Goaway => write!(f, "Goaway(0x({:02x}))", self.0),
            H2FrameType::WindowUpdate => write!(f, "WindowUpdate(0x({:02x}))", self.0),
            H2FrameType::Continuation => write!(f, "Continuation(0x({:02x}))", self.0),
            _ => write!(f, "FrameType::Unknown(0x({:02x}))", self.0),
        }
    }
}