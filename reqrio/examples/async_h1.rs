use std::error::Error;
use reqrio::{json, AcReq, Buffer, ReqExt, Timeout, WsFrame, WsOpcode, ALPN};
use reqtls::{rand, Fingerprint, RecordLayer};

fn get_frame_len(frame: &Buffer) -> Result<usize, Box<dyn Error>> {
    if frame.len() < 2 { return Err("data len not enough".into()); }
    let second = frame[1];
    let mask = (second & 0x80) != 0;
    let mut payload_len = (second & 0x7F) as usize;
    let mut header_len = 2; // 基础头部
    if payload_len == 126 {
        if frame.len() < 4 { return Err("data len not enough".into()); }
        payload_len = u16::from_be_bytes([frame[2], frame[3]]) as usize;
        header_len += 2;
    } else if payload_len == 127 {
        if frame.len() < 10 { return Err("data len not enough".into()); }
        payload_len = u64::from_be_bytes([
            frame[2], frame[3], frame[4], frame[5],
            frame[6], frame[7], frame[8], frame[9]
        ]) as usize;
        header_len += 8;
    }
    if mask {
        header_len += 4;
    }
    Ok(header_len + payload_len)
}

fn get_payload(mut buffer: Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
    if buffer.len() == 0 { return Err("data is empty".into()); }
    if buffer[0] & 0x80 != 0x80 {
        // warn!("[Websocket] Not a final packet!");
        return Err("Not a final frame!".into());
    }
    let mut payload_len = (buffer[1].clone() & 0x7F) as usize;
    Ok(match payload_len {
        127 => {
            let mut pl = [0; 8];
            for (i, d) in buffer[2..10].iter().enumerate() {
                pl[i] = *d;
            }
            payload_len = u64::from_be_bytes(pl) as usize;
            if buffer.len() < payload_len + 10 { return Err("data len not enough".into()); }
            let msg = buffer[10..payload_len + 10].to_vec();
            // buffer.copy_within(payload_len + 10..buffer.len(), 0);
            // buffer.set_len(buffer.len() - payload_len - 10);
            // buffer = buffer[payload_len + 10..].to_vec();
            msg
        }
        126 => {
            payload_len = u16::from_be_bytes([buffer[2], buffer[3]]) as usize;
            if buffer.len() < payload_len + 4 { return Err("data len not enough".into()); }
            let msg = buffer[4..payload_len + 4].to_vec();
            // buffer.copy_within(payload_len + 4..buffer.len(), 0);
            // buffer.set_len(buffer.len() - payload_len - 4);
            // frame = frame[payload_len + 4..].to_vec();
            msg
        }
        _ => {
            if buffer.len() < payload_len + 2 { return Err("data len not enough".into()); }
            let msg = buffer[2..payload_len + 2].to_vec();
            // buffer.copy_within(payload_len + 2..buffer.len(), 0);
            // buffer.set_len(buffer.len() - payload_len - 2);
            // frame = frame[payload_len + 2..].to_vec();
            msg
        }
    })
}

#[tokio::main]
async fn main() {
    // let fingerprint = Fingerprint::new_ja4("t13d1517h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,0029,002b,002d,0033,44cd,fe0d,ff01_0403,0804,0401,0503,0805,0501,0806,0601").unwrap();
    //
    // let mut data =hex::decode("1603010848010008440303a5fb6638dbe64a35a0d500e2c3465316d1617310d498ca2e4b18f13158d05ae820818c23e338779d38edc46c29cbcfe73cf201099adf60663710d364a34a32ae9300200a0a130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035010007db5a5a0000000a000c000a9a9a11ec001d0017001800170000003304ef04ed9a9a00010011ec04c056633ea1c8b22e71a2f7c904acaa009265b1b0a87ed2ba7cba078a5dc1c3c0310a1857bc613036acb7ba384a4a442c3661f580c150bc8e8a36d6461397757d90ab92bf5929ef7108dbd49b373692dfd72b20068c5e8b2a2390a6768ac7b7d25708f167c232027f3b31f1478cb01963b65b855f281bbbc8b7f5a377fe5cc03a22a974c232056505003ac439a8777a3112adcc8bc06092fde299bc8a9b8c9970ffb75e864c8546caaa1db27dd9da62b5c6cdca672017282bafc133f1a0086e265338cc7812282653d5a442fc1c7e89cb6d7665a9097f4f55b34abc0cd2288cbfd9628cdaa434e521fb07671007b55de167e76b0b28c7a6b53476ed51409c088a8d08b5298965c35179ae283514150b8e446a39e1c74a801825f1c6bb0612ce7618d3841b09035bd029b14dc30d944603dd4b02da117f87c056b2961596545bff02291ad03c06810da5e08a4df82c61ac32d93ba00f7ca7cf865bae27c0d9a86ade5872ad55ce8e5589daa64cfcda74eb535514d94633383efd90831f2b20f3f8847fa87ede43352ff6a6031598d7c27c8a0b6921caa87e67b63c7acdb91c24b3499eb1795e885212003bbbe06838f2189c8940771d03b845e314297934d5970f6c0c26aad41f419c7d8c9a9aa2521a94b40102d3037796c8fb48292a99a4519574c7e4162a2bac9e9b32fd0ba5e0eb8f8fe86ad8346e0fe93f21997708eab3024ba6fa4972456653cd412e2f737ee645571dc71befb945dcd13ad21c8e78f1a6a0fa06b86c0797512613bb30c556a1c6331d5b6a12b914ceaaa008737cc9ecd4b19fc3c20386209d7c73ac046f8de3a20a8c5292556ae719018933525d7b17b39a92cf2aa8b44a9e9c3c17c16a3bec82669d1345e72b1dddd87aa7e1c214e3a0e2a028e95347c4e75f4d641ad438798fb5408ac65c7b028caa8929699ccb7225b253d90cfa7b3375b2a94c47cdf012821e199457a1ca4eb0c504c21edcc5b251eca83204cd91927b0687b407a94a2a4ca6e78134a59351c7788118a96ccb84b8e5018f253a6e822a10b9bbaaa3f507391879c40795c0ec09af33b44dd24c7a6c835596837249a7f1aa135cfb5df1937664138bf8301419781371ea3736441c94c1400fb385386885f85b9724bb6fa4e48733279ee308a38a297bde67b5d535837a29541874bf3b04209de00d2ec96472bc1612b438a2e86035581c36f18737f4313acb7db943c4e9175f472470d698245e5b6e7e6b1983c40fa762829e7746adf4cb2bab469b67432bdb61a5d68d86ca8a4366255f406064c89129d6307a199b21e3b2c2137239c80e5823b527bb494ef55787d688fd3866a58b41268a873e9239c8312ce4c66fdc44525660a7af300b40d04afb9c18225c5be134b17fa76ec06abaf901646869ab8d9bcff0f7527ec83427180149c85963d3c16b856b2e58bd9b6022186009918290c4cc90e912856b005a7670a3f1206839abafa2b8bbeb1a704a678d65901184ab35b9473d947abab0ec554246cac6117388ea73f3b61ef0764a754a7489720db575c06cd057d54ca87a9698a1d2a714a33d35805bb89b320f97b4d8a06cbfb30aa4a66baf018d72b86cf6dc49c1dc31973297808b7b915909838a1da1f039ca77ce78ea67dd244b5443efd97378404e4fb0699cd5e6c7931db067bf2df9e1d77609491b07daaba5b65e82a09d28c44d95b8998508063a1b2b001d0020138ea9a7ea4607ef11eae91e6988e5ee5d58ea0c6e44f063b657992ef339c111000500050100000000fe0d011a0000010001da002087f1d8249e0d7cce5fa9053729d3b8c4507f6750bb224f8a02ffe17a0c0d040800f0d58e03e7ecc019e4c8002d1dc18cf86669baba6dfb38178c09fed01970a433fc9d04991edcec696f41cc05a9624d9d53ca53bb5227c25d783cc2708bf542b6dda1868a20d169689386740b6e234f704b45f99cdbe09eddbbf08165a6b1be6c1cd99c8a9dc8cd7ebfc72b8da524d42f9a3b73b3522a5adbd31a59f39fb831d3e85486c688de034ab6b8fb0db84cfd9c1c6ce87d7315685d3831c8132fd7d59b9537b15bdbe53e33f1db367efe7a9bbadc8c3f54c8975745a7aba861cd9e46646e226418fb3ed6671c52f8738bd8347817db6199a75424347dcd45bd367b45308fbccc5bd3b3b4fef8d9e405635f0d2eb20010000e000c02683208687474702f312e31000b0002010000120000ff01000100001b000302000200230000000d001200100403080404010503080505010806060144cd00050003026832002b0007064a4a03040303002d000201010000001500130000107073732e62647374617469632e636f6d6a6a0001000029012b00f600f0a12f8633d2ea22594d2f008edf7444396846a0514a20366cd35ab17e7e5cf11fcb8914653b99ce6b63fd6cae843e5445b53a39f9f686e34e4889336a517feb03010478f14030a20554ce2225cf43debc8d3ecadd885ea1bab8670bfc202084fb6b319d98b9976449179de7c0c50fef02ff275c16b2873093d556daa01b197aa54b5c454b92ce2c5f252b813348f4aa49d1e25268e51ce0f469b395cf6091138a941f40dcf8e6ab678fa09ca00ecfe0fa2dba363d2cece4e31333d0f6d32be86bfe5499a70934a4abda27916734ea471eb06e0097e395f77b510d7409382a4a039b67451fc5e6dcf2ecc0a43b5c337507acc19724003130e5a357d4ca7911dec46b84a44a09d2c9160f7aafbf3518d0ae2f7544961de8ded7f072f1d1bcc9aeab74241ffc6c99f9").unwrap();
    // //
    // let record = RecordLayer::from_bytes(&mut data, false).unwrap();
    // println!("{:#?}", record);
    // let mut req = AcReq::new().with_alpn(ALPN::Http11);//.with_fingerprint(fingerprint)
    let headers = json::object! {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "Cookie": "pac_uid=0_NattYaCs7NNmH; omgid=0_NattYaCs7NNmH; _qimei_uuid42=19c1f11150d1000f92fe16d850a9c40cf94ef1d39f; _qimei_fingerprint=f3dc39297e432b1f08da57e9904a8f52; _qimei_q36=; _qimei_h38=a549811f92fe16d850a9c40c02000006b19c1f; _qpsvr_localtk=0.2296543129537577; RK=WPZCq/wl3I; ptcz=c338dead622f05f0d8467ac10589e7e45326b81d67ff476b9643f933cfdc644a; eas_sid=M1b7q677w9D5R5P2L8x5g4p313; eas_entry=https%3A%2F%2Fgraph.qq.com%2F; POESESSID=939e23af876572a0b2852b2e183e20cc",
        "Host": "m.so.com",
        "Pragma": "no-cache",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": 1,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0",
        "sec-ch-ua": r#""Microsoft Edge";v="143", "Chromium";v="143", "Not A(Brand";v="24""#,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": r#""Windows""#
    };
    // req.set_headers_json(headers).unwrap();
    // // // let fingerprint = Fingerprint::new_ja3("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,13-11-65037-17613-45-18-16-5-43-10-0-27-23-35-51-65281,4588-29-23-24,0").unwrap();
    // // // println!("{:#?}", fingerprint);
    // // let fingerprint = Fingerprint::random().unwrap();
    // // req.set_fingerprint(fingerprint);
    // // // req.set_proxy(Proxy::HttpPlain(Addr::new_addr("125.121.47.165", 13968)));
    // req.set_callback(|body| {
    //     println!("{}", body.len());
    //     Ok(())
    // });
    // // // req.set_alpn(ALPN::Http11);
    // // // let content = req.gen_h1().unwrap();
    // // // println!("{}", String::from_utf8(content).unwrap());
    // req.set_url("https://www.baidu.com").await.unwrap();
    // // // sleep(Duration::from_secs(5)).await;
    // let res = req.get().await.unwrap();
    // println!("{} {}", res.header(), res.raw_body().len());
    // // // req.set_url("https://s.360.cn/mso/disp.gif?pro=m_so&pid=result&u=https%3A%2F%2Fm.so.com%2Fs%2F&guid=15015764.1071255116101212729.1764940193317.2156&mbp=0&q=2132&pq=&ls=&abv=&ablist=&sid=f057cafe91decc82f2436391559db2ef&qid=&src=default_src&srcg=default_srcg&userid=&nid=&version=&category=&nettype=unknown&nav=&chl=&bv=&adv_t=&end=0&bucketid=240001%2C350001%2C530001%2C540001%2C750000%2C830003%2C850001%2C920000%2C1230007%2C1330000%2C1550001%2C1900000%2C2260000%2C3030000%2C4130001%2C4260003%2C4700001%2C4770001%2C4810001%2C5010000%2C5070001%2C5120001%2C5150001%2C5400001%2C5510001%2C5740001%2C5790002%2C5810001%2C5910000%2C6000001%2C6310000%2C6480001%2C6490003%2C6620003%2C6660026%2C6920004%2C7170013%2C7190023%2C7660000%2C8020016%2C8060001%2C8190001%2C8310002%2C8330001%2C8480001%2C8530000%2C8570012%2C8640000%2C8720001%2C8890000%2C8980000%2C9000019%2C9060001%2C9110001%2C9130000%2C9260001%2C9270003%2C9330000%2C9390002%2C9560000%2C10720005%2C10820001%2C10950003%2C10990001%2C11010003%2C11120001%2C11140000%2C11180001%2C11270000%2C11460000%2C11500002&pn=1&bzv=584d8cd4518f3435&screen=1&mod=ccb&cat=time-filter&t=1767332302637").await.unwrap();
    // // // let res = req.get().await.unwrap();
    // // // println!("{}", res.header());
    // // // req.set_url("https://s.360.cn/mso/disp_srp.gif?pro=m_so&pid=result&u=https%3A%2F%2Fm.so.com%2Fs%2F&guid=15015764.1071255116101212729.1764940193317.2156&mbp=0&q=2132&pq=&ls=&abv=&ablist=&sid=f057cafe91decc82f2436391559db2ef&qid=&src=default_src&srcg=default_srcg&nettype=unknown&nav=&end=0&pn=1&psid=&af=0&dpi=1920_1200&dpr=1&dr=&ssl=1&p1=0&p3=&p2=1&t=1767332302636").await.unwrap();
    // // // let res = req.get().await.unwrap();
    // // // println!("{}", res.header());
    // // // req.set_url("https://s.360.cn/mso/srp.gif?pro=m_so&pid=result&u=https%3A%2F%2Fm.so.com%2Fs%2F&guid=15015764.1071255116101212729.1764940193317.2156&mbp=0&q=2132&pq=&ls=&abv=&ablist=&sid=f057cafe91decc82f2436391559db2ef&qid=&src=default_src&srcg=default_srcg&userid=&nid=&version=&category=&nettype=unknown&nav=&chl=&bv=&adv_t=&end=0&bucketid=240001%2C350001%2C530001%2C540001%2C750000%2C830003%2C850001%2C920000%2C1230007%2C1330000%2C1550001%2C1900000%2C2260000%2C3030000%2C4130001%2C4260003%2C4700001%2C4770001%2C4810001%2C5010000%2C5070001%2C5120001%2C5150001%2C5400001%2C5510001%2C5740001%2C5790002%2C5810001%2C5910000%2C6000001%2C6310000%2C6480001%2C6490003%2C6620003%2C6660026%2C6920004%2C7170013%2C7190023%2C7660000%2C8020016%2C8060001%2C8190001%2C8310002%2C8330001%2C8480001%2C8530000%2C8570012%2C8640000%2C8720001%2C8890000%2C8980000%2C9000019%2C9060001%2C9110001%2C9130000%2C9260001%2C9270003%2C9330000%2C9390002%2C9560000%2C10720005%2C10820001%2C10950003%2C10990001%2C11010003%2C11120001%2C11140000%2C11180001%2C11270000%2C11460000%2C11500002&pn=1&bzv=584d8cd4518f3435&ob=0&box_list=&ob_map=&om=5&om_list=0%3Amso-og-goods-list%2C1%3Amso-app-download%2C5%3Amso-app-download%2C8%3Amso-baike%2C11%3Amso-app-download&en=0&en_list=&mb=5&mb_list=top-rec%2C3%3Amso-recommend-normal-rel-1_top%2C4%3Aown_guide_recommend%2C7%3Amso-recommend-normal-rel-1_bottom%2Cnew-rel&mods=rec_top%2Crec_nlp%2Crec_guide%2Crec_nlp%2Cnew-rel&toptype=wap%2Cwap%2Cweb&psid=&af=0&tg=&dpi=1920_1200&dpr=1&dr=&ssl=1&unionid=&p1=0&p3=&wap=5&web=5&t=1767332302635").await.unwrap();
    // // // let res = req.get().await.unwrap();
    // // // println!("{}", res.header());
    // // // req.set_url("https://s.360.cn/mso/disp.gif?pro=m_so&pid=result&u=https%3A%2F%2Fm.so.com%2Fs%2F&guid=15015764.1071255116101212729.1764940193317.2156&mbp=0&q=2132&pq=&ls=&abv=&ablist=&sid=f057cafe91decc82f2436391559db2ef&qid=&src=default_src&srcg=default_srcg&userid=&nid=&version=&category=&nettype=unknown&nav=&chl=&bv=&adv_t=&end=0&bucketid=240001%2C350001%2C530001%2C540001%2C750000%2C830003%2C850001%2C920000%2C1230007%2C1330000%2C1550001%2C1900000%2C2260000%2C3030000%2C4130001%2C4260003%2C4700001%2C4770001%2C4810001%2C5010000%2C5070001%2C5120001%2C5150001%2C5400001%2C5510001%2C5740001%2C5790002%2C5810001%2C5910000%2C6000001%2C6310000%2C6480001%2C6490003%2C6620003%2C6660026%2C6920004%2C7170013%2C7190023%2C7660000%2C8020016%2C8060001%2C8190001%2C8310002%2C8330001%2C8480001%2C8530000%2C8570012%2C8640000%2C8720001%2C8890000%2C8980000%2C9000019%2C9060001%2C9110001%2C9130000%2C9260001%2C9270003%2C9330000%2C9390002%2C9560000%2C10720005%2C10820001%2C10950003%2C10990001%2C11010003%2C11120001%2C11140000%2C11180001%2C11270000%2C11460000%2C11500002&pn=1&bzv=584d8cd4518f3435&mod=recb&screen=1&p_list=0%2C1%2C2%2C3%2C4%2C5%2C6%2C7%2C8%2C9&logid=1&cat=toprecommend&eci=&nlpv=&t=1767332302638").await.unwrap();
    // // // let res = req.get().await.unwrap();
    // // // println!("{}", res.header());
    // // // let mut res = req.get().await.unwrap();
    // // // println!("{}", res.header());
    // // // println!("{}", res.decode_body().unwrap().as_bytes().unwrap().len());
    // // // println!("{:#?}", req.header().cookies());
    // //
    // // // let jump = "https://e.so.com/jump?u=http%3A%2F%2Fewfbrsqu.wfquanaigou.cn%2F&m=a625dc&from=m.so.com&monitor=pro%3Dm_so%26pid%3Dresult%26u%3Dhttps%253A%252F%252Fm.so.com%252Fs%252F%26guid%3D13928712.2099131224995151211.1766337767018.3141%26mbp%3D2%26q%3Dewfbrsqu.wfquanaigou.cn%26pq%3D%26ls%3D%26abv%3D%26ablist%3D%255B%255D%26sid%3D56e0f68394e00ee73ca2263b502bd982%26qid%3D%26src%3Dmsearch_next_input%26srcg%3Dhome_next%26userid%3D%26nid%3D%26version%3D%26category%3D%26nettype%3Dunknown%26nav%3D%26chl%3D%26bv%3D%26adv_t%3D%26end%3D0%26pn%3D1%26bzv%3D584d8cd4518f3435%26mod%3Dog%26pos%3D1%26type%3Dweb%26official%3D0%26pcurl%3Dhttp%253A%252F%252Fewfbrsqu.wfquanaigou.cn%252F%26data-md-b%3Dtitle%26screen%3D1%26scrTime%3D3%26af%3D%26clicktype%3Dlink%26value%3Dhttp%25253A%25252F%25252Fewfbrsqu.wfquanaigou.cn%25252F%26t%3D1766337768188";
    // // // req.set_url(jump).await.unwrap();
    // // // req.insert_header("Sec-Fetch-Site", "same-site").unwrap();
    // // // let res = req.get().await.unwrap();
    // // // println!("{}", res.to_string().unwrap());
    let mut timeout = Timeout::new();
    timeout.set_read(99999);
    timeout.set_write(99999);
    timeout.set_handle(99999);
    let mut req = AcReq::new();
    req.set_timeout(timeout);
    req.set_url("https://poe.game.qq.com/").await.unwrap();
    let context = r#"GET wss://poe.game.qq.com/api/trade2/live/poe2/%E7%93%A6%E5%B0%94%E7%9A%84%E5%AE%BF%E5%91%BD/32Y6Wjkc5 HTTP/1.1
Host: poe.game.qq.com
Connection: Upgrade
Pragma: no-cache
Cache-Control: no-cache
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0
Upgrade: websocket
Origin: https://poe.game.qq.com
Sec-WebSocket-Version: 13
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
Cookie: pac_uid=0_NattYaCs7NNmH; omgid=0_NattYaCs7NNmH; _qimei_uuid42=19c1f11150d1000f92fe16d850a9c40cf94ef1d39f; _qimei_fingerprint=f3dc39297e432b1f08da57e9904a8f52; _qimei_q36=; _qimei_h38=a549811f92fe16d850a9c40c02000006b19c1f; _qpsvr_localtk=0.2296543129537577; RK=WPZCq/wl3I; ptcz=c338dead622f05f0d8467ac10589e7e45326b81d67ff476b9643f933cfdc644a; eas_sid=M1b7q677w9D5R5P2L8x5g4p313; eas_entry=https%3A%2F%2Fgraph.qq.com%2F; POESESSID=939e23af876572a0b2852b2e183e20cc
Sec-WebSocket-Key: Y/3ZjeJohL99ku1nNT2WEQ==
Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits

"#.replace("\n", "\r\n");
    let resp = req.h1_io(context.as_bytes().to_vec()).await.unwrap();
    println!("{}", resp.raw_string());
    let mut buffer = Buffer::with_capacity(0xFFFF);

    let mut req2 = AcReq::new().with_alpn(ALPN::Http20);
    req2.set_headers_json(headers).unwrap();
    loop {
        req.stream.async_read(&mut buffer).await.unwrap();
        while let Ok(frame) = WsFrame::from_buffer(&mut buffer) {
            match frame.frame_type().op_code() {
                WsOpcode::TEXT => println!("text-{:?}", frame.payload().len()),
                WsOpcode::PING => {
                    println!("PING-{}", frame.payload().len());
                    let pong = WsFrame::new_pong(true, frame.payload().as_bytes());
                    let bs=pong.to_bytes();
                    println!("pong={:?}", bs);
                    req.stream.async_write(&bs).await.unwrap();
                }
                _ => println!("other-{}-{:?}", frame.payload().len(), frame.payload().as_bytes())
            }
        }
    }
}