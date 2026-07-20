use std::fmt::{Debug, Formatter};
use crate::{Buf, BufferError, ReadExt, Reader, WriteExt};


pub struct Parameter<'a> {
    flag: u64,
    value: Buf<'a>,
}

impl<'a> Debug for Parameter<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}({:?})", self.spec(), self.value)
    }
}

impl<'a> Parameter<'a> {
    pub fn spec(&self) -> &str {
        match self.flag {
            0x00 => "original_destination_connection_id",
            0x01 => "max_idle_timeout",
            0x02 => "stateless_reset_token",
            0x03 => "max_udp_payload_size",
            0x04 => "initial_max_data",
            0x05 => "initial_max_stream_data_bidi_local",
            0x06 => "initial_max_stream_data_bidi_remote",
            0x07 => "initial_max_stream_data_uni",
            0x08 => "initial_max_streams_bidi",
            0x09 => "initial_max_streams_uni",
            0x0a => "ack_delay_exponent",
            0x0b => "max_ack_delay",
            0x0c => "disable_active_migration",
            0x0d => "preferred_address",
            0x0f => "initial_source_connection_id",
            0x11 => "version_information",
            0x20 => "max_datagram_frame_size",
            0x3127 => "google_initial_rtt",
            _ => "Reversed",
        }
    }


    pub fn from_reader(reader: &mut Reader<'a>) -> Result<Parameter<'a>, BufferError> {
        let typ = crate::quic::read_variant(reader)? as u64;
        let len = crate::quic::read_variant(reader)?;
        let buf = Buf::Ref(reader.read_slice(len)?);
        Ok(Parameter {
            flag: typ,
            value: buf,
        })
    }

    pub fn len(&self) -> usize {
        match self.flag {
            ..0x40 => 1 + self.value.len(),
            0x40..0x40FF => 2 + self.value.len(),
            0x40FF..0x40FF_FFFF => 4 + self.value.len(),
            0x40FF_FFFF..0x40FF_FFFF_FFFF_FFFF => 8 + self.value.len(),
            _ => unreachable!()
        }
    }

    pub fn write_to<W: WriteExt>(self, writer: &mut W) -> Result<(), BufferError> {
        crate::quic::write_variant(self.flag as usize, writer)?;
        crate::quic::write_variant(self.value.len(), writer)?;
        writer.write_slice(self.value.as_ref())
    }
}