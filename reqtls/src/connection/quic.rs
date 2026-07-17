use crate::error::RlsResult;
use crate::extend::Aead;
use crate::hash::HashError;
use crate::message::{PacketType, QUICFlag, QUICPacket};
use crate::suite::TlsCipher;
use crate::{Buf, Buffer, BufferError, Cipher, HashType, Hkdf, ReadExt, Reader, WriteExt};
use std::error::Error;
use std::fmt::{Display, Formatter};
#[cfg(feature = "log")]
use log::trace;
use crate::buffer::CipherDecodeBuffer;
use crate::suite::iv::Iv;

#[derive(Debug)]
pub enum QUICError {
    InvalidVarint,
    Buffer(BufferError),
    Hash(HashError),
}

impl Error for QUICError {}

impl Display for QUICError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<BufferError> for QUICError {
    fn from(e: BufferError) -> Self {
        QUICError::Buffer(e)
    }
}

impl From<HashError> for QUICError {
    fn from(e: HashError) -> Self {
        QUICError::Hash(e)
    }
}

pub struct QUICConnection {
    client_cipher: TlsCipher,
    server_cipher: TlsCipher,
    client_sample: Cipher,
    server_sample: Cipher,
    buffer: Buffer,
}

impl Default for QUICConnection {
    fn default() -> Self {
        QUICConnection {
            client_cipher: TlsCipher::none(),
            server_cipher: TlsCipher::none(),
            client_sample: Cipher::aes_128_ecb(),
            server_sample: Cipher::aes_128_ecb(),
            buffer: Buffer::default(),
        }
    }
}


impl QUICConnection {
    const INIT_SLAT: [u8; 20] = [56, 118, 44, 247, 245, 89, 52, 179, 77, 23, 154, 230, 164, 200, 12, 173, 204, 187, 127, 10];
    pub fn read_varint(reader: &mut Reader) -> Result<usize, QUICError> {
        let flag = reader.current();
        println!("{:?}", flag);
        match flag >> 6 {
            0b00 => Ok(reader.read_u8()? as usize),
            0b01 => Ok((reader.read_u16()? & 0x3FFF) as usize),
            0b10 => Ok((reader.read_u32()? & 0x3FFF_FFFF) as usize),
            0b11 => Ok((reader.read_u64()? & 0x3FFF_FFFF_FFFF_FFFF) as usize),
            _ => Err(QUICError::InvalidVarint)
        }
    }

    /// [rfc9001 5.2](https://datatracker.ietf.org/doc/html/rfc9001#name-initial-secrets)
    pub fn init(&mut self, flag: u8, dcid: &[u8], server: bool) -> RlsResult<()> {
        if flag & 0x30 != PacketType::Initial as u8 { return Ok(()); };
        // #[cfg(feature = "log")]
        // println!("[QUIC] dcid={}", hex::encode(dcid));
        let mut hkdf = Hkdf::new(&Self::INIT_SLAT, dcid, HashType::Sha256)?;
        let mut init_secret = [0; 32];
        hkdf.hkdf("tls13 client in", b"", &mut init_secret)?;
        let mut hkdf = Hkdf::from_prk(&init_secret, HashType::Sha256);
        let mut key = [0; 16];
        hkdf.hkdf("tls13 quic key", b"", &mut key)?;
        let mut iv = [0; 12];
        hkdf.hkdf("tls13 quic iv", b"", &mut iv)?;
        let mut hp_key = [0; 16];
        hkdf.hkdf("tls13 quic hp", b"", &mut hp_key)?;
        match server {
            true => {
                self.server_cipher.set_key(&key, &[], &Aead::AES_128_GCM, HashType::Sha256)?;
                self.server_cipher.set_iv(Iv::new(&iv, vec![]));
                self.server_sample.set_secret_key(hp_key, None);
            }
            false => {
                self.client_cipher.set_key(&key, &[], &Aead::AES_128_GCM, HashType::Sha256)?;
                self.client_cipher.set_iv(Iv::new(&iv, vec![]));
                self.client_sample.set_secret_key(hp_key, None);
            }
        }
        Ok(())
    }

    ////[rfc9001](https://datatracker.ietf.org/doc/html/rfc9001#name-header-protection-sample)
    pub fn read(&mut self, origin: &[u8], server: bool) -> RlsResult<()> {
        let mut reader = Reader::from_slice(origin);
        let flag = reader.read_u8()?;
        let mut packet = QUICPacket::default();
        if flag & 0x80 == 0x80 {
            //LongHeader
            packet.ver = reader.read_u32()?;
            let dcid_len = reader.read_u8()? as usize;
            packet.dc_id = Buf::Ref(reader.read_slice(dcid_len)?);
            self.init(flag, packet.dc_id.as_ref(), server)?;
            let scid_len = reader.read_u8()? as usize;
            packet.sc_id = Buf::Ref(reader.read_slice(scid_len)?);
            if flag & 0x30 == 0 {
                let tk_len = QUICConnection::read_varint(&mut reader)?;
                packet.token = Buf::Ref(reader.read_slice(tk_len)?);
            }
            packet.len = QUICConnection::read_varint(&mut reader)?;
            let pn_offset = reader.position();
            #[cfg(feature = "log")]
            trace!("[QUIC] read: dcid={:?}; scid={:?}; token={:?}",packet.dc_id, packet.sc_id, packet.token);
            let sample_offset = pn_offset + 4;
            let sample = &origin[sample_offset..sample_offset + 16];
            let mut mask = match server {
                true => self.server_sample.encrypt(sample)?,
                false => self.client_sample.encrypt(sample)?,
            };
            mask.truncate(5);
            packet.flag = QUICFlag::from_u8(flag ^ (mask[0] & 0x0f));
            let offset = 0..pn_offset + packet.flag.num_len();
            packet.hdr_len = offset.len();
            packet.hdr_raw[offset.clone()].copy_from_slice(&origin[offset]);
            packet.hdr_raw[0] ^= mask[0] & 0x0f;
            packet.hdr_raw[pn_offset..pn_offset + packet.flag.num_len()].iter_mut().enumerate()
                .for_each(|(i, x)| *x ^= mask[i + 1]);
            let mut decode_reader = Reader::from_slice(&packet.hdr_raw);
            decode_reader.set_position(pn_offset);
            packet.num = match packet.flag.num_len() {
                1 => decode_reader.read_u8()? as u64,
                2 => decode_reader.read_u16()? as u64,
                3 => decode_reader.read_u24()? as u64,
                4 => decode_reader.read_u32()? as u64,
                _ => unreachable!()
            };
            reader.set_position(decode_reader.position());
            let pd_len = packet.len - packet.flag.num_len();
            packet.payload = Buf::Ref(reader.read_slice(pd_len)?);
            println!("{:#?}", packet);
            self.decode(&packet)?;
        }
        Ok(())
    }


    fn decode(&mut self, packet: &QUICPacket) -> RlsResult<()> {
        let buffer = CipherDecodeBuffer::from_quic(packet, self.buffer.unfilled())?;
        self.client_cipher.decrypt(Some(packet.num), buffer)?;
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use crate::connection::quic::QUICConnection;

    #[test]
    fn test_quic_read() {
        let raw = hex::decode("cc000000010803a13a23b2df2956000044d0d69062cdfb1003761ddcd1a869dc4f3125fc1284f346c486fc6e9d6403d78ac0b3d26997c2582df4d779f86c79c409faf347bd5f3e1e84c68346f1ee1b4a3985720bd6e2559a996c459290a69d53e21980a47f1e40849bb5ca88d0da7499827f70992993ebb959db98352b70fdd056ceca13e6064bb9b1f1d2b35c9846fa56af9822ce2cf8d1bea65574432c9aba555be8c034afcc1910a1822dae93c38942e150cef54c3f695f1c7e20222bc88092ffb9a0ab7b1b0f7b234b56e329a10057576ee2c2a9696a0add8428e1f843f7e320530ea94eb98e1bed904115a43ffc80f726b206e20bcbee132d11c414da72c0f60f6b2accf8e7815b22122717fc83ef5151f7934b0b118c6a016ca595524cb7116e35e71e690b9e5f0cb4cdc3d1d9d494800c3aeb93d010741b0497dd1c1f7c1eb2602baa15373f57a5e15c10e2798d6ba9707af92c529f34059127063db641af004c5c2ed4d72dfcf992bd751c35965deab53c1ce1bc1cc61b49cef6290a51552cc11e0ee6c235d6a09babe822425eadb4ecdd61fbef87c2148addb0de83685108e5f4b2d3193bd86629876499df69aef4b0e51be2dbf48379c8877c283ae63492da3d19567e3a4d199aab9a14a6974f551b63cc315bbf8e0b52fb48fda0b1deda31828f104f1e3f57e888667249a6edbf2841704546a4b5b080957ab35252050d0c349b575794980eb4ce1222a84066cfecb607e78b870241c8d9a9eefce9566424ad36c1348ee27e10ab3cc58143031ef20abeae10d4817dddbf0d4f0cf789daed51f07730a8438f81c3f3099e5b76a105d2532cc24b65fad4f5485e9112de65c0251ab85f71f77b3ddea66725f755db58305c410549b474cd435dbf8c5a9855a0007722e93d8c1f062cd4f4dace2d8f4cf174cc3e8b268b8d574630d43d40ea55c3916892b94be94f0f80ff335610bd1b391ef1bf639672a75055018dcd291fbad8b466a42e8622699768f533a9f127c7be23d984d9ed3e85d89007ea4dbde271eb77bca4e3171afa0089a6feac5f1ab2051e4201a6e11e43749c78513aeb9a4c47717a042005360924a239657a8148ee7524df09d03b635f43f83d912362eefe4b4d6b6287abf3098457ab62b1785def3c6b53dd798efb9a4a8e0c11506d179101f9877a1b8b27624a61d050b3b8dd89a770c830a831261b85e8a02f126aaa328176a95cccb16f553fa49003fa19d10ce05ef38bb5003dee4b03e736c8b96c1f6a2cb58a1977112cf2ffd4110acdb50cca3a99a044d421173fb20c667b39c793ec650071591b454969a7bb89847aaac3c028052304b635c0051f21e4f733e930409c230743e81c8f4ff3662bfafbd540a7e382fa856969afe08cbee9d9bce92c0f9dc2be5a336267ec88440793188ec6f41e8125f8263849ea3355487858baee98bfd7a78a72ce7c4a2b2ac37a5975765486a76450396b6ea1390b86b9e6f36740554cfb7b03c80e5129c5be9d6e8138f0a59526f8ed8f161ccf94fca8e826e9b91b218362f2233be00f07ee6833b2d6cff06bbd0051b7c68de3c7bf0f957c63ad52c3f491f9af7d837fb7ce9a1f7c7bf013adebba7d34852f98c515ae278d76fdfaa133ea02959d22b85d521dcfe3cdb113606be5d70ef0762398b583380dbabc37d1e0b99fae0c7d9f8f8f543d6a356e35a5d994d659245ff16b2f9e7036668b81386abfccfa19c7442a98cf4a82cebb57e51d5a0dc1ec14d25ac6a0f8").unwrap();
        let mut conn = QUICConnection::default();
        conn.read(&raw, false).unwrap();
    }
}