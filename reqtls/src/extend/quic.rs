use crate::Buf;

#[repr(C)]
#[derive(Clone)]
#[cfg_attr(debug_assertions, derive(Debug))]
pub struct QUICParameter<'a> {
    flag: u64,
    value: Buf<'a>,
}

impl<'a> QUICParameter<'a> {
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

    pub const fn new(flag: u64, value: Buf<'a>) -> QUICParameter<'a> {
        QUICParameter {
            flag,
            value,
        }
    }
}