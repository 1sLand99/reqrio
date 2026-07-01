use reqtls::Buf;

#[repr(u8)]
pub enum PacketType {
    Padding = 0x00,
    Ping = 0x01,
    Ack = 0x02,
    AckEcn = 0x03,
    ResetStream = 0x04,
    StopSending = 0x05,
    Crypto = 0x06,
    NewToken = 0x07,
    Stream(u8),
    MaxData = 0x10,
    MaxStreamData = 0x11,
    MaxStreamsBidi = 0x12,
    MaxStreamsUni = 0x13,
    DataBlocked = 0x14,
    StreamDataBlocked = 0x15,
    StreamsBlockedBidi = 0x16,
    StreamsBlockedUnu = 0x17,
    NewConnectionId = 0x18,
    RetireConnectionId = 0x19,
    PathChallenge = 0x1a,
    PathResponse = 0x1b,
    ConnectionCloseTrp = 0x1c,
    ConnectionCloseApp = 0x1d,
    HandshakeDone = 0x1e,

}

pub struct QuicPacket<'a> {
    flag: u8,
    ver: u32,
    dc_id: Buf<'a>,
    sc_id: Buf<'a>,
    token: Buf<'a>,
    num: u32,
    payload: Buf<'a>,
}
