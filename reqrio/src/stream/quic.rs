use crate::error::HlsResult;
use reqtls::quic::*;
use reqtls::{Buf, Buffer, WriteExt};
use std::io::Write;
use std::net::{SocketAddr, UdpSocket};
use std::ops::Range;
use std::{mem, slice};
// pub struct QUICStreamS {
//     stream: UdpSocket,
//     reader_buffer: Buffer,
//     writer_buffer: Buffer,
//     buffer: Buffer,
//     conn: QUICConnection,
// }
//
// impl QUICStreamS {
//     pub fn new(stream: UdpSocket) -> QUICStreamS {
//         QUICStreamS {
//             stream,
//             buffer: Buffer::default(),
//             conn: QUICConnection::default(),
//         }
//     }
// }
//
// impl StreamHandle for QUICStreamS {
//     fn stream_param(&mut self) -> (&mut Buffer, StreamParam<'_>) {
//         (&mut self.reader_buffer, StreamParam {
//             handshake_finish: &mut false,
//             encrypted_channel: &mut false,
//             hello_retrying: &mut false,
//             write_buffer: &mut Default::default(),
//             conn: &mut Default::default(),
//         })
//     }
// }


pub struct UDPStreamS {
    socket: UdpSocket,
    buffer: QUICBuffer,
    write_buffer: Buffer,
    conn: QUICConnection,
    sent: Vec<Range<usize>>,
    addr: SocketAddr,
}

impl UDPStreamS {
    pub fn send_frames(&mut self, frames: Vec<FrameType>, pd_len: usize) -> HlsResult<()> {
        let mut packet = QUICPacket::new_initial(1, pd_len);
        packet.set_hdr_len(self.conn.cid().len(), 0);
        self.conn.make_cipher(0x30, false)?;
        println!("hdr_len: {}", packet.hdr_len());
        //head+pd+tag
        self.write_buffer.check_move(packet.hdr_len() + pd_len + 16)?;
        let start = self.write_buffer.end();
        //需要写入头部
        self.write_buffer.add_len(22);
        for frame in frames {
            frame.write_to(&mut self.write_buffer)?;
        }
        let offset = start..self.write_buffer.end();
        self.write_buffer.add_len(16);

        let ptr = self.write_buffer.raw_ptr_mut();
        let buf = unsafe { slice::from_raw_parts_mut(ptr.add(start), offset.len()) };
        self.conn.make_message(buf, &mut packet)?;
        self.socket.send_to(buf, self.addr)?;
        self.sent.push(offset);
        Ok(())
    }
}

impl Write for UDPStreamS {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut frames = vec![FrameType::Ping];
        for (i, chunk) in buf.chunks(350).enumerate() {
            frames.push(FrameType::Crypto {
                offset: i * 350,
                value: Buf::Ref(chunk),
            });
            let size = frames.iter().map(|x| x.len()).sum::<usize>();
            if size + 350 >= 1210 {
                self.send_frames(mem::take(&mut frames), size)?
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use crate::hex;
    use crate::stream::quic::UDPStreamS;
    use reqtls::quic::{QUICBuffer, QUICConnection};
    use reqtls::Buffer;
    use std::io::Write;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};

    #[test]
    fn test_udp_stream() {
        let mut stream = UDPStreamS {
            socket: UdpSocket::bind("0.0.0.0:0").unwrap(),
            buffer: QUICBuffer::with_capacity(1500),
            write_buffer: Buffer::with_capacity(16438),
            conn: QUICConnection::default(),
            sent: vec![],
            addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(124, 72, 128, 203), 443)),
        };
        let client_hello = hex::decode("16030108080100080403035cc0ca906bb559aac3b8973ead29a0ba8fe44c6d49c4e014f0eb8cef0143e96020bd4398de18812cc4474b9d4d983b9e2c54aad8f8636bbc2c000b4ec3782166230020dada130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f00350100079bcaca0000003304ef04ed1a1a00010011ec04c0e2ca7e6acb4a7bd48cc6267659cc683854471b181fd6e07de6b231427b129759bc60325d4d02453e11425b720e1da783282b7f0b927bf3677c3cf80aac149df44a65dbc7b3013a1176c6cfa2170613730a8d4335ec6c8398ab2fde274b3c4a1b02d34fd4d1cd4f672411580c1f776b2947682b137f56197fc57319ab47521f624107191ce85a46a9e43abb572b089918a63178abdacd37796f80d4586a419187f8983f8c0486024912d9c8822660b8957ad5c57a034932bce9c325523bb4d06556f5b5c36a50bbec0538436a20f05d74bcbbe1431767b08eb81b125a252acc1605408b238d22498330a3d5f8bd625704d12289502a0fae1b48dcfb53fb17669632aa2ef876b826861f2164be5141d17aa140523d7676acbae670ae3767dc8009d9e61d510a311d185716c066714c9bc99851e3d22a7f9132ae3845e52a0048f3cc994376d4e1844a961ec3781edd1979a8741fe2f51bc01b542ce2596dea80ea910282f27bf847b64b69c5f8d83142d37c9dc1c27944b6637a9c855b587422bcb458460666b8a9356c13c37918f76866f289fbb74337d866e8f2c9bf23826707981546a9a2154030d06989799390c490c80228bb9389e541c0d91bc69bdb730019a02e5357ab5bb395231a59b90002903a8dc241aa170b76cba25a6c2b24f804b0c729747960d2e23f6c2987ade48680d0c1151a843f103b3df21767dc3f52fa16080b28ebb8b8ba944e884729478c3532d73a9568589904069095aa55897b5bfa72188170115525f19b5103528b48d78a27da34e881b10d0b43f043b50c6b8848e2b5f3564a9ad03ea3165cd5805a086c3323b73aec9522f30cb15c78cff24c6051e31e1658ce31d574d694260dd664b86845adc0cdd7c27525f6c8d3f8806205caa6324d8f9ba2cde866350586932c128b0240f82329413a369d07b6f1f2bc82a892e224088f8b79c7671beca6cc45d30f79298ee1b34a59ca9740636876b9a24c1c844d088a1256a4ed0937a82ac456cc8e37007c5cd163f3b48c6d938ad1250774e51303e88790b5191f695df171b1107b7ddac45385a54bc913553ec1caa8375869930e103b5f054487e49721ea8827bc74117b6c5e263170e359162e8442812cc5af308293187999f53ff9362f28825f451cc58fba6430f10380742f5bf2622e4753ea10445fd93c197283756a9f17e3b45d865722f2b4f81badfbc407f15a87cb426dfc713063511539784006429cb1c59df35619f6bc864516333bf4257bdca6c9aa4865b5b2e4d05a1773ae78f995298a28f78158dd45b1bee69b49c38955f7a135e1695a8371ed603ce8b566d426a86c526c8f226fd66c6dd0639006d71d74e8224cc9ac2aa99c3ba26f8bc5674c420850574044f52118f8caaac033ae5a4857555ff8876df488be04982b35574f633ac77da8b2eccb07a8544ed714bcf0e87828463a6ca864da07427577945df1877c760123462c07802880e71dfb730777e11a3500642f5a4bac503e5fdbcb74bc5e281b8ec7608dc02037bdca2fe98534c886beabb3078c52a706939938670baf6103a4b2a71d37c538cb308c7040e11b8362f5c16fd2c3470405e3b1b54e17509f7aa4e9eca7ab2533f0753f13d1c3e70db469cec138195c26dfa6e913c1502ff673ad89da782d5730e7839118f185d4853613fb27fafbd6fcdeabac8cbd2cb54ff7cab98b8e18bade73322c001d00208dbd5ea8a10fcf78c32564f41837a5227c5f9e33cab7e8420ad9675e73b99d7ffe0d00fa0000010001bb002012000839e58c06e36d44cb0f67bbf609915d8584b23b7c196c4c5112a6fbb80200d0580b447bf18bb437b89de89306b701f5def505e76dd50fcba098f1281014e2cbd0fe83207c30326cf527df277c7204edff3119ed4a5162336ca0e422390601dbe608cab030267a0031eaaed54c5948d1a5a4ae89885e04f10d436821c9d8ad925f785587b7efe0bc46b6191ba4b043eb45c441ba3b08bef2ebdeb84e03d25068234d403f340fd1df03115ffd2d60ef46f97fbebe634bad9b0dcfc839b501f30f0c3335691b9a9340017994f3beb571322319fcbc82df8c75e1b4f296f90dbb97dfbecde6326748f7a2264ca0922c1bb00012000000000010000e00000b636e2e62696e672e636f6d002b0007068a8a0304030344cd000500030268320023011400000000215c0fdeab332447b6ded6ec22c2b5e159c9e120eab2e827b4f3774e0e81ec972b74abc57914c670caff95f2b1499553eda241a4402063954e5456d6636c68be77d16c2ef3eb90ca6f0b6c06531bbd8ac4097f8be3048c04d8c4538e62455f9a1d5bc0bf0c74714355d98ab2ae4d46a0f8f53255fc81ee25dc70ad4528d275ac9b9f2d586c99d8618c1effd06dff7b97d0d01000f7228796bcbe3e9b0f05f9a49f0db4e80fdb122e998cf9df3574692449c00acb19e89775f93e84fd3da79fe55d8cdbbe76ed950ef55fa6b3fe4b1fd23df5e00d539a739169d8147a4d65e3e7ff8a0550ff84423255fc997028140c9add4a31b25f6496f7f8a5154650a38164d5b25049c1427fe85cf9efe847da2a27000b000201000010000e000c02683208687474702f312e31000a000c000a1a1a11ec001d00170018001b0003020002000d0012001004030804040105030805050108060601002d0002010100050005010000000000170000ff010001000a0a000100").unwrap();
        stream.write_all(&client_hello).unwrap();
    }
}