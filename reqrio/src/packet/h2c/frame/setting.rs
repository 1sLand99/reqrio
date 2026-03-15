use reqtls::WriteExt;
use crate::error::HlsResult;

#[derive(Clone, Debug)]
pub enum H2Setting {
    HeaderTableSize(u32),
    EnablePush(u32),
    MaxConcurrentStreams(u32),
    InitialWindowSize(u32),
    MaxFrameSize(u32),
    MaxHeaderListSize(u32),
}

impl H2Setting {
    pub fn from_bytes(context: &[u8]) -> HlsResult<H2Setting> {
        let k = u16::from_be_bytes([context[0], context[1]]);
        Ok(match k {
            0x1 => H2Setting::HeaderTableSize(u32::from_be_bytes(context[2..6].try_into()?)),
            0x2 => H2Setting::EnablePush(u32::from_be_bytes(context[2..6].try_into()?)),
            0x3 => H2Setting::MaxConcurrentStreams(u32::from_be_bytes(context[2..6].try_into()?)),
            0x4 => H2Setting::InitialWindowSize(u32::from_be_bytes(context[2..6].try_into()?)),
            0x5 => H2Setting::MaxFrameSize(u32::from_be_bytes(context[2..6].try_into()?)),
            0x6 => H2Setting::MaxHeaderListSize(u32::from_be_bytes(context[2..6].try_into()?)),
            _ => return Err(format!("frame byte error: {:?}", context).into()),
        })
    }

    pub fn write_to<W: WriteExt>(&self, writer: &mut W) {
        match self {
            H2Setting::HeaderTableSize(v) => {
                writer.write_u16(0x1);
                writer.write_ru32(v, false);
            }
            H2Setting::EnablePush(v) => {
                writer.write_u16(0x2);
                writer.write_ru32(v, false);
            }
            H2Setting::MaxConcurrentStreams(v) => {
                writer.write_u16(0x3);
                writer.write_ru32(v, false);
            }
            H2Setting::InitialWindowSize(v) => {
                writer.write_u16(0x4);
                writer.write_ru32(v, false);
            }
            H2Setting::MaxFrameSize(v) => {
                writer.write_u16(0x5);
                writer.write_ru32(v, false);
            }
            H2Setting::MaxHeaderListSize(v) => {
                writer.write_u16(0x6);
                writer.write_ru32(v, false);
            }
        }
    }

    pub fn default() -> Vec<H2Setting> {
        vec![
            H2Setting::HeaderTableSize(65535),
            H2Setting::EnablePush(0),
            H2Setting::InitialWindowSize(6291456),
            H2Setting::MaxHeaderListSize(242144)
        ]
    }
}