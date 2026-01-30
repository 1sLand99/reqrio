use crate::error::HlsResult;

#[derive(Clone, Debug)]
pub enum Setting {
    HeaderTableSize(u32),
    EnablePush(u32),
    MaxConcurrentStreams(u32),
    InitialWindowSize(u32),
    MaxFrameSize(u32),
    MaxHeaderListSize(u32),
}

impl Setting {
    pub(crate) fn from_bytes(context: &[u8]) -> HlsResult<Setting> {
        let k = u16::from_be_bytes([context[0], context[1]]);
        Ok(match k {
            0x1 => Setting::HeaderTableSize(u32::from_be_bytes(context[2..6].try_into()?)),
            0x2 => Setting::EnablePush(u32::from_be_bytes(context[2..6].try_into()?)),
            0x3 => Setting::MaxConcurrentStreams(u32::from_be_bytes(context[2..6].try_into()?)),
            0x4 => Setting::InitialWindowSize(u32::from_be_bytes(context[2..6].try_into()?)),
            0x5 => Setting::MaxFrameSize(u32::from_be_bytes(context[2..6].try_into()?)),
            0x6 => Setting::MaxHeaderListSize(u32::from_be_bytes(context[2..6].try_into()?)),
            _ => return Err(format!("frame byte error: {:?}", context).into()),
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Setting::HeaderTableSize(v) => {
                let mut res = 0x1u16.to_be_bytes().to_vec();
                res.extend(v.to_be_bytes());
                res
            }
            Setting::EnablePush(v) => {
                let mut res = 0x2u16.to_be_bytes().to_vec();
                res.extend(v.to_be_bytes());
                res
            }
            Setting::MaxConcurrentStreams(v) => {
                let mut res = 0x3u16.to_be_bytes().to_vec();
                res.extend(v.to_be_bytes());
                res
            }
            Setting::InitialWindowSize(v) => {
                let mut res = 0x4u16.to_be_bytes().to_vec();
                res.extend(v.to_be_bytes());
                res
            }
            Setting::MaxFrameSize(v) => {
                let mut res = 0x5u16.to_be_bytes().to_vec();
                res.extend(v.to_be_bytes());
                res
            }
            Setting::MaxHeaderListSize(v) => {
                let mut res = 0x6u16.to_be_bytes().to_vec();
                res.extend(v.to_be_bytes());
                res
            }
        }
    }

    pub fn default() -> Vec<Setting> {
        vec![
            Setting::HeaderTableSize(65535),
            Setting::EnablePush(0),
            Setting::InitialWindowSize(6291456),
            Setting::MaxHeaderListSize(242144)
        ]
    }
}