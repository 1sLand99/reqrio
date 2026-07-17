use crate::error::RlsResult;
use crate::extend::Aead;
use crate::hash::HashError;
use crate::message::{Frame, PacketType, QUICFlag, QUICPacket};
use crate::suite::TlsCipher;
use crate::{message, Buf, Buffer, BufferError, Cipher, HashType, Hkdf, ReadExt, Reader, WriteExt};
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
                let tk_len = message::read_varint(&mut reader)?;
                packet.token = Buf::Ref(reader.read_slice(tk_len)?);
            }
            packet.len = message::read_varint(&mut reader)?;
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
        let len = self.client_cipher.decrypt(Some(packet.num), buffer)?;
        self.buffer.add_len(len);
        let mut reader = Reader::from_slice(self.buffer.filled());
        let mut frames = Vec::with_capacity(30);
        while reader.unread_len() > 0 {
            let frame = Frame::from_reader(&mut reader)?;
            println!("{:?}", frame);
            frames.push(frame);
        }

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
        let raw = hex::decode("c4000000010803a13a23b2df2956000044d0b664765eb6b0f164bb4706766edbaada206afcd8b9f01240e661df2d2fadb65939820d202be6cea66ae723de1bff79dcd9541f22274a0093521df4b49c6d3e1b1b2951c52db14b446d321986e757acbf4decd5dd1668a4bc9157b60bf053c7d7b85d1fa3d09d5ce630c4b2b761401f0bcc8e325c661229a1d420198acec592570da0f9578b366337985e95ff22bf80efc629d93bbb2b50dc4e7a7dec9c07e35e933a653280d9830d1c5c2a45a7f0b22153a118fe2946af5aa686a23d72635d6cdc880af0cec870fd30885fed4f4313103f0ed74e4e13c49f125bf918a88d7a66013d449c91ceed7e21e50d778c3333b001b43f34d18a1ef04d43cbc375326bc8d0998a15a65a300f248f94975fa0e02d1006f45f8643de4ea64d2bc8be140900fe58ab03cff38bbc96071b313c22b1ebe3c3eff2856d77c7e367ba33663ec0c67a6ea04af8bf188e6d1ba612c84bd58af0ea6f37ed296be44e1a5877b1a38c34280eef53e1cfcc6cbc6c00d405d80205b98259e10df8c4ae0d08d0071980a5cd3b9d8733a0345e0fec0b18b5ced8cacbbdbc093603c5cfaabd85f51972588c45dfe5f4a422f1615a0cca25a1be86f47e078a275b4e562e927b6528b804b45b14770277e4daba5fda03786a11d0e7c42e270171773e5782a5cfd6a24c745b59e8ee8f1ba77311393ea721836f97c6482091daa75436bc8a31698a58442702584f04b545436471e72c2ed68b7610c63b32ea1365ac812b9cc88b33ceb7ecaf1f6d6d106e4507a5a0b0b4fcab0fd74bbad05c89d5c5a0f09435573be3d3f819f0dbdf660796e75e6f50cf640952afd326e6082a32ff066399b22853628816d7cf4935a1d6967dd80bac483ec5c30af3fb9d65ed8914e7e8f2f66d08627982dae63c3606942ad7880d85aba920c7256a6c59fe2ad71b221fff7eb705decce0b38965234a639debdd36817c31a4df091c3e94bda0c0c1d514c74f9adb8d7952f6b8b6b6c7771a62cb04c472dd2898038ee1b28c991f29c2ea9f7713db6311bcd96abcc8e754feb7fa70dd212acfc4efc674d83c8a3e7f957026ab8e39a0ed3279c18349b704ec4675c7ada87107dcefbd7b5ec819f390a0114acfbefc2cecfe00ba2a20cc74cebedcd423f81537ef78230b0c174795bfe1789dc56be8f13caa999f6baf11d85e748c59ddca4d058de64e555981af445493785ca77c60c72837037a48bc317c4ea1f99dec546be5bedae3b7535e601c85f43f823b08d98bdcba868c11bf8aed7f3b5b352b103c19a3a7b2005cf15293e39c098357f549730948ad26c631f93177094ac11fef523b97f98789184e2cc5c057a3bd727332e596226c25534c2a21b8d8eb4f33223d30c8055205153cbaa5e61a807b6ebef95b5aea398425c6add9c806a6320b514cd39f5b7f0344c19f60ccf54c5e6e26a6693512a5f671d9640eb5259775707c89a6b27fa83cf9bdc45b0071a2a5a3594233f21b2d69fadaab5534796fc3462e72a3e5608dfe2ab1207874b0f4970b43ef9f25ac169b9cb6fb144aa1ac223bdabf2e9aa19a51ed865a79ae97e8f9b5492faa4ad9ac075ecd4ed7dbcf7b73b2cd8612b21291eaca34f8d4107767454326bf40f1b4bcefe98b0807a54e0e02b41ead1011a817ef2e42d7a4bdd53aa543ec30d8cfb5fc090a5bdb52ac2e075f44122b28bbbe12151dfd6fa9c7f93e1681d609f923f195e4e831d0bd42aeab44b48de4a532ae97365d").unwrap();
        conn.read(&raw, false).unwrap();
    }
}