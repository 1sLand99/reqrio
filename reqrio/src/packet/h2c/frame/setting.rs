use reqtls::WriteExt;
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

    pub fn write_to<W: WriteExt>(&self, writer: &mut W) {
        match self {
            Setting::HeaderTableSize(v) => {
                writer.write_u16(0x1);
                writer.write_ru32(v, false);
            }
            Setting::EnablePush(v) => {
                writer.write_u16(0x2);
                writer.write_ru32(v, false);
            }
            Setting::MaxConcurrentStreams(v) => {
                writer.write_u16(0x3);
                writer.write_ru32(v, false);
            }
            Setting::InitialWindowSize(v) => {
                writer.write_u16(0x4);
                writer.write_ru32(v, false);
            }
            Setting::MaxFrameSize(v) => {
                writer.write_u16(0x5);
                writer.write_ru32(v, false);
            }
            Setting::MaxHeaderListSize(v) => {
                writer.write_u16(0x6);
                writer.write_ru32(v, false);
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