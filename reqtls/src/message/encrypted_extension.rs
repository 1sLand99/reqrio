use crate::error::RlsResult;
use crate::message::HandshakeType;
use crate::{BufferError, Extension, WriteExt};

#[derive(Debug)]
pub struct EncryptedExtension<'a> {
    handshake_type: HandshakeType,
    extensions: Vec<Extension<'a>>,
}

impl<'a> EncryptedExtension<'a> {
    pub fn from_bytes(ht: HandshakeType, bytes: &'a [u8]) -> RlsResult<EncryptedExtension<'a>> {
        let len = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
        Ok(EncryptedExtension {
            handshake_type: ht,
            extensions: Extension::from_bytes(&bytes[6..6 + len], false)?,
        })
    }

    pub fn len(&self) -> usize {
        6 + self.extensions.iter().map(|x| x.len(false)).sum::<usize>()
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) -> Result<(), BufferError> {
        writer.write_u8(self.handshake_type.as_u8())?;
        writer.write_u32(self.len() as u32 - 4, true)?;
        writer.write_u16(self.len() as u16 - 6)?;
        for extension in self.extensions {
            extension.write_to(writer, false)?
        }
        Ok(())
    }
}