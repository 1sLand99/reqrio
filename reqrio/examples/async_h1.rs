use reqrio::*;

#[tokio::main]
async fn main() {
    let mut timeout = Timeout::new();
    timeout.set_connect(30000000);
    timeout.set_handle(300000000);
    timeout.set_read(99999999999);
    timeout.set_write(99999999999);
    timeout.set_handle_times(3);
    // let fingerprint = Fingerprint::from_ja3("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0", "4b107bbnbc-01o-3781k7bbnbc-01v25461k").unwrap();
    // let fingerprint = Fingerprint::from_ja4("t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01_0403,0804,0401,0503,0805,0501,0806,0601", "4b107bbnbc-01o-3781k7bbnbc-01v25461k").unwrap();
    // let fingerprint = Fingerprint::from_hex_all("160301072401000720030347c8885be57c7b5ef724505f486efff05173d7ac332ff5764b7509f845f2f4cd20ea5e1d057803dd84d88a0e0d0ba7578e38bfb307cd60808f710d100c13bda4110020dada130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035010006b71a1a0000002d00020101000b00020100000500050100000000003304ef04edfafa00010011ec04c0c399b44b802ea789831e2625ebd68a136b713e80a50233a22dbc8002a6aab07ba3afd935e2f315ddb72dfa4a94f75a7494da759b03780f558a3d0a0608a38d8af2122d1ccca3a9121b5387e9da46d913b539b0c9d6b4a68a9a15f825892b26ce70815b159a7dee77ab7ea5b4fd30b9f202818ba6c7551a65f011654307b334716e667651c4e7a2a5e14ff43b271fe627273246268628157b641a62751e30b263657f160868d8d7b8095439d97941759874943c6a12da92b7d146e4e870a4e90541a23b7c5ab1c6448f7188563a097c5f78a349073737d7a37cdb08bcb09ca6dc31b4229260d88a93c7a948411e7da3b309c41987771bf8c71151aa9bc4369f1515463587c42387bb48c52846491b1d9227c0686fa1549246f44424aa258e443b431096ec2ccd377a88e24c98229236fa016bab815466c40eeae134ca77704348a2b6627cbed551d1ea0daf635206d425f600c73edc4b98c02bdf0b5efc7b73ce75a2924043e2436c944771630259f0516b30b529a64062b3098dc8343852e598887c88dbaa0b2c709b1a58941916ba4edb9caec90eb6f930f9da5cb58bb855862b59263eeda31d2a06a89763b838d10f6a0c3199c1b10bcc9d1549b0e860a1f0901698c350b7eb5e86104ff631361fd6beec2c77806362833c2efa3063810c86faa7b5ab92389eab258320265fb23f0d7a2b3a9aad03c94604cb43d532376314b2e8d4cfedda36b578b590e6146ea18c6847a0569c8318a68620f294e9d9875d014549695bd3ca68c430577092a375ac3a37203a0336c1e134b45af2548bccc8ce075e4e74a370f16d4bcbc90c8cb42ed09b5dd05c620528d9dac66833bc02e7734967c6a7cc4bebe95b85d7275b976c9ac0997eb264a0a684d4279512054a3258a39e604f1ec148ca2130d29a1ab92b53c1b0ab4ee3805f339201e968847b78739175fd695181b7a7ce500bd31a0685926e04d5ce6d2b612845ba68d39f617c21afa75f26bca95c17507698af280c0c5f21890ab78a8e56b1e94509b226066624a7c6701c3ae461c54161e7d5760279acc167cc01908b7d4a19576459e9b6276ce2c791990851fb9f8b197cf0c96de1fb61cd1c13c222c5194182edc4695e295d54a506fa09b0881169a6f32a8afc0acd5644876b5e698105f36a56a16aaf49041ea34a92619969b983025d585ee6f1bcfa131e995431b2b3a68b514534a599af1c13ad095d38cb458a1a8ac7f51524503166a63cf6d8963aa89a20c37013984672f79a9be13f93719d89e765a82a4775d531b3ebcb8b4c2935510ba6a770bc10a8a4ec60f01a9a20250050d96c535454f5b69b8cf8c00c44790f3964a1f4b2fabc5a85f061348c89e3ba1797c0c26bf3bbcad70d93822f932a18ca7ca0cf866c6b1b4de2571606f01eb2e5ab3be719c91370f29363a218aacf40284dc6c3c59671df4b62d5e44e81039c3498248a7659f0074996533e8097a0aee389a6d9ae9364b3a64bcf4e576f67802b89943ae03a24d2772726887f5fc803933111d4aa35da30a78b560bb4ec2dc918a3998281f046093f897919078ebdf05ec7f7ce03311a79bc49cb537322e8c6a6abbe56a55f6e1555e384ba6fa9c4f8e0189d3650c26aee67cbe704d7465022c259b6534361651c9b6d71fc98e18f84ff8aa1f3e880bcdbd8eddd440e3d7e99580bd9bc7f83f444daa761442c1a625dc5d44da361001d0020afa0c21e9ab34f115732ecb8e6b5d83379c4660811738d8be560cafde446fd0b00000020001e00001b6d63732d6d696d702d7765622e73662d657870726573732e636f6d002b0007064a4a03030303000a000c000afafa11ec001d0017001800230000001b000302000244690005000302683100170000fe0d011a0000010001960020cb3de92f31efcfcd5a53c79fbe3200c1f481e37199aa290649f1abad6ed5031e00f0dcb724c041356d77ecf7cf213696ee291b549ee48b028251d6ddde9865586ea997acd0a5210799395fd9682738cf609dd99a9c829efbc5ba83ffc2d8932b551886b5c1ebc1ac1233273e5ccfe8fa1e50fb0812f05f0fcb607672a934c778acc998173d746e8672f2aa6b60efa66369ffd7c03b9d7dcf3fc3f0cdb255347d8394dae22615b14c5ff626fa8e65b5d93278da980f307f21af1a124cab78db6d41d1cfe69d7f1ab90038f7d209f85e7d7d5ad045a2ca484569320dcae3f33b163992f0e68268899d3dabdb83f3177f115f97d165ba545ef9c193a16abc8ad3b24d458af544fb553218136e8dfa1230aa000c0010000e000c02683108687474702f312e3100120000000d0012001004030804040105030805050108060601ff01000100eaea00010016030300251000002120db295d27307243c8688dc4c8136ad6241713f787a2a6554d616e27965b789a41140303000101", "273j677n7c-j191b2a3k677n7c3o3--u263k").unwrap();
    // let fingerprint = Fingerprint::random("273j677n7c-j191b2a3k677n7c3o3--u263k").unwrap();
    // let certs = Certificate::from_pem_file("/home/xl/1/client.crt").unwrap();
    // let key = RsaKey::from_pri_pem_file("/home/xl/1/client.key").unwrap();
    let mut req = AcReq::new()
        // .with_fingerprint(fingerprint)
        .with_alpn(ALPN::Http11)
        .with_timeout(timeout)
        .with_verify(false)
        // .with_mtls(certs, key)
        // .with_proxy(Proxy::try_from("http://127.0.0.1:10240").unwrap())
        ;
    let headers = json::object! {
        // "Authorization": "Bearer Upy9fDyueOXiEbON0vRXimg4tlrO5wTs+IV75wUbSzZngY0oLn1wJpQw1jnV0Cqku1UUnDUvVg4y/wwkNOljlJJKVRbzDETSjOd0zHotk+s3+wM63SDWeKXOXKwUhhfc",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        "Accept": "*/*",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Dest": "document",
        "sec-fetch-user":"?1",
        "upgrade-insecure-requests":"1",
        "sec-ch-ua": "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Microsoft Edge\";v=\"120\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\"",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Accept-Encoding": "gzip,deflate,br,zstd",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        // "cookie":"JSESSIONID=05304295A550FF08DE1E44A03CDA8CBB; acw_tc=0a065e4717701411754903815e64f1c251caacb791decd35981b455583d1da; acw_sc__v2=69823a8cb1bb76098533c5837be7f69784d38872"
    };
    req.set_headers_json(headers).unwrap();
    // let data = json::object! {
    //   "alpn": "http/1.1",
    //   "body": "",
    //   "headers": {
    //     "Accept": "*/*",
    //     "Accept-Encoding": "gzip, deflate, br, zstd",
    //     "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
    //     "Cache-Control": "no-cache",
    //     "Connection": "keep-alive",
    //     // "Content-Type": "application/x-www-form-urlencoded",
    //     "Pragma": "no-cache",
    //     // "Referer": "http://xxxxxx",
    //     "Sec-Fetch-Dest": "empty",
    //     "Sec-Fetch-Mode": "cors",
    //     "Sec-Fetch-Site": "same-origin",
    //   },
    //   "method": "GET",
    //   "tls": "Chrome-linux-135",
    //   "url": "https://m.baidu.com"
    // };
    // req.set_url("https://shopee.tw/").await.unwrap();
    // req.set_url("https://127.0.0.1:3453/v1/api/tlsReq").await.unwrap();
    // req.set_json(data);
    // req.set_auto_redirect(false);
    req.set_url("http://zwfw.hubei.gov.cn/web/user/uias_login.do?appCode=hbzwfw&gotoUrl=http%3A%2F%2Fzwfw.hubei.gov.cn%2Fwebview%2Fgrkj%2Fwelcome.html&p01=").await.unwrap();
    // req.set_url("https://127.0.0.1:7878").await.unwrap();
    // req.set_url("https://www.jetstar.com").await.unwrap();
    // req.set_url("https://m1.pxb7.com/api/search/h5/product/selectSearchPageList").await.unwrap();
    // req.set_url("https://www.link114.cn/").await.unwrap();
    //
    // req.set_url("https://accounts.pcid.ca/login").await.unwrap();
    // req.set_url("https://xxbg.snssdk.com/fdsf/dsfsdfkdsjfk").await.unwrap();
    // req.set_url("https://www.toutiao.com/article/7600224020776239658/?log_from=99ab1fa2b852c_1769590891442&wid=1769590984039").await.unwrap();
    // req.set_url("https://www.sogou.com").await.unwrap();
    // req.set_url("https://cn.bing.com/search?q=site%EF%BC%9Asite：wLLyn.com&first=0&FORM=PERE2").await.unwrap();
    // req.set_url("https://m.baidu.com").await.unwrap();

    // req.set_url("https://m.so.com").await.unwrap();
    // req.set_url("https://www.sephora.com/beauty/giftcards").await.unwrap();
    // req.set_url("https://doc.rust-lang.org/").await.unwrap();
    // req.set_url("https://tls.123408.xyz/api/clean").await.unwrap();
    // req.set_url("https://mcs-mimp-web.sf-express.com/mcs-mimp/sendValidCode").await.unwrap();
    // req.set_callback(|data| {
    //     println!("{}", data.len());
    //     Ok(())
    // });
    // req.set_url("https://jetstar.com").await.unwrap();
    // req.set_url("https://127.0.0.1:8000").await.unwrap();
    // req.set_auto_redirect(false);
    // let url = "https://oauth.hubei.gov.cn:8443/";
    // req.set_url(url).await.unwrap();
    let res = req.get().await.unwrap();
    println!("{}", res.header());
    // req.set_url(res.header().location().unwrap()).await.unwrap();
    // let res=req.get().await.unwrap();
    // println!("{}",res.header());
    // println!("{}", res.raw_body().len());
    // println!("{}", res.header().content_type().is_some());
    // println!("{}", res.text().unwrap());
    // req.set_url(res.header().location().unwrap()).await.unwrap();
    // let res = req.get().await.unwrap();
    // println!("{}", res.header());
}