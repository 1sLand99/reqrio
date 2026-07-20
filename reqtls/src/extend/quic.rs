use std::fmt::{Debug, Formatter};
use crate::{Buf, BufferError, ReadExt, Reader};

///[rfc9001 Transport Parameter Definitions](https://datatracker.ietf.org/doc/html/rfc9000#name-transport-parameter-definit)
#[allow(non_camel_case_types)]
#[repr(u64)]
pub enum Parameter<'a> {
    original_destination_connection_id(Buf<'a>) = 0x00,
    max_idle_timeout(Buf<'a>) = 0x01,
    stateless_reset_token(Buf<'a>) = 0x02,
    max_udp_payload_size(Buf<'a>) = 0x03,
    initial_max_data(Buf<'a>) = 0x04,
    initial_max_stream_data_bidi_local(Buf<'a>) = 0x05,
    initial_max_stream_data_bidi_remote(Buf<'a>) = 0x06,
    initial_max_stream_data_uni(Buf<'a>) = 0x07,
    initial_max_streams_bidi(Buf<'a>) = 0x08,
    initial_max_streams_uni(Buf<'a>) = 0x09,
    ack_delay_exponent(Buf<'a>) = 0x0A,
    max_ack_delay(Buf<'a>) = 0x0b,
    disable_active_migration(Buf<'a>) = 0x0c,
    preferred_address(Buf<'a>) = 0x0d,
    initial_source_connection_id(Buf<'a>) = 0x0f,
    version_information(Buf<'a>) = 0x11,
    max_datagram_frame_size(Buf<'a>) = 0x20,
    google_initial_rtt(Buf<'a>) = 0x3127,
    Reversed { flag: u64, value: Buf<'a> },
}

impl<'a> Debug for Parameter<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Parameter::original_destination_connection_id(v) => write!(f, "original_destination_connection_id({:?})", v),
            Parameter::max_idle_timeout(v) => write!(f, "max_idle_timeout({:?})", v),
            Parameter::stateless_reset_token(v) => write!(f, "stateless_reset_token({:?})", v),
            Parameter::max_udp_payload_size(v) => write!(f, "max_udp_payload_size({:?})", v),
            Parameter::initial_max_data(v) => write!(f, "initial_max_data({:?})", v),
            Parameter::initial_max_stream_data_bidi_local(v) => write!(f, "initial_max_stream_data_bidi_local({:?})", v),
            Parameter::initial_max_stream_data_bidi_remote(v) => write!(f, "initial_max_stream_data_bidi_remote({:?})", v),
            Parameter::initial_max_stream_data_uni(v) => write!(f, "initial_max_stream_data_uni({:?})", v),
            Parameter::initial_max_streams_bidi(v) => write!(f, "initial_max_streams_bidi({:?})", v),
            Parameter::initial_max_streams_uni(v) => write!(f, "initial_max_streams_uni({:?})", v),
            Parameter::ack_delay_exponent(v) => write!(f, "ack_delay_exponent({:?})", v),
            Parameter::max_ack_delay(v) => write!(f, "max_ack_delay({:?})", v),
            Parameter::disable_active_migration(v) => write!(f, "disable_active_migration({:?})", v),
            Parameter::preferred_address(v) => write!(f, "preferred_address({:?})", v),
            Parameter::initial_source_connection_id(v) => write!(f, "initial_source_connection_id({:?})", v),
            Parameter::version_information(v) => write!(f, "version_information({:?})", v),
            Parameter::max_datagram_frame_size(v) => write!(f, "max_datagram_frame_size({:?})", v),
            Parameter::google_initial_rtt(v) => write!(f, "google_initial_rtt({:?})", v),
            Parameter::Reversed { flag, value } => write!(f, "reversed(flag: {:?}, value: {:?})", flag, value),
        }
    }
}

impl<'a> Parameter<'a> {
    pub fn from_reader(reader: &mut Reader<'a>) -> Result<Parameter<'a>, BufferError> {
        let typ = super::super::message::read_variant(reader)? as u64;
        let len = super::super::message::read_variant(reader)?;
        let buf = Buf::Ref(reader.read_slice(len)?);
        Ok(match typ {
            0x00 => Parameter::original_destination_connection_id(buf),
            0x01 => Parameter::max_idle_timeout(buf),
            0x02 => Parameter::stateless_reset_token(buf),
            0x03 => Parameter::max_udp_payload_size(buf),
            0x04 => Parameter::initial_max_data(buf),
            0x05 => Parameter::initial_max_stream_data_bidi_local(buf),
            0x06 => Parameter::initial_max_stream_data_bidi_remote(buf),
            0x07 => Parameter::initial_max_stream_data_uni(buf),
            0x08 => Parameter::initial_max_streams_bidi(buf),
            0x09 => Parameter::initial_max_streams_uni(buf),
            0x0a => Parameter::ack_delay_exponent(buf),
            0x0b => Parameter::max_ack_delay(buf),
            0x0c => Parameter::disable_active_migration(buf),
            0x0d => Parameter::preferred_address(buf),
            0x0f => Parameter::initial_source_connection_id(buf),
            0x11 => Parameter::version_information(buf),
            0x20 => Parameter::max_datagram_frame_size(buf),
            0x3127 => Parameter::google_initial_rtt(buf),
            _ => Parameter::Reversed { flag: typ, value: buf },
        })
    }

    pub fn len(&self) -> usize {
        // match self {
        //     Parameter::original_destination_connection_id(_) => {}
        //     Parameter::max_idle_timeout(_) => {}
        //     Parameter::stateless_reset_token(_) => {}
        //     Parameter::max_udp_payload_size(_) => {}
        //     Parameter::initial_max_data(_) => {}
        //     Parameter::initial_max_stream_data_bidi_local(_) => {}
        //     Parameter::initial_max_stream_data_bidi_remote(_) => {}
        //     Parameter::initial_max_stream_data_uni(_) => {}
        //     Parameter::initial_max_streams_bidi(_) => {}
        //     Parameter::initial_max_streams_uni(_) => {}
        //     Parameter::ack_delay_exponent(_) => {}
        //     Parameter::max_ack_delay(_) => {}
        //     Parameter::disable_active_migration(_) => {}
        //     Parameter::preferred_address(_) => {}
        //     Parameter::Reversed { .. } => {}
        // }
        0
    }
}


// #[derive(Debug)]
// pub struct TrpParam {
//     typ: Parameter,
//     value: u32,
// }