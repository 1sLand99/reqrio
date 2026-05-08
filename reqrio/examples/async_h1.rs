use std::time::Duration;
use tokio::time::sleep;
use reqrio::*;

#[tokio::main]
async fn main() {
    let fingerpirnt = Fingerprint::from_hex_all("1603010200010001fc0303daf602c8f741db35b1ce2fa67c4edd38a6a21e22e9e78a563a3433551102a2a6201f0910cad3e2496077c3102b9d64adf9dd177622a1e3f3bb77dd17659e9559970020caca130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035010001931a1a000000000018001600001368352e6d6f757461693531392e636f6d2e636e00170000ff01000100000a000a0008eaea001d00170018000b00020100002300000010000e000c02683208687474702f312e31000500050100000000000d0012001004030804040105030805050108060601001200000033002b0029eaea000100001d002006648fc930928438e9a9a9f495a947ef0fa1592c42ba347ee73df14376ef0346002d00020101002b000b0adada0304030303020301001b00030200024469000500030268323a3a000100001500c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "2f-o7ffnfc-j2f7q7n-k7ffnfc-m423p26-k").unwrap();
    println!("{:#?}",fingerpirnt.tls().build_client_hello().unwrap());
    let mut header = Header::try_from(r#"
Host: h5.moutai519.com.cn
Connection: keep-alive
MT-V: faadf75ac25d8abe0f27732f3fj
MT-Device-ID: clips_cEEkFiIXJkByQXJDJRB0R3cWIUR8TylPKRouGH5JcA==
Content-Web-Bb: 87e543a10f6d5cb28987e543a10f6dcbef8c47bc549abfc3ea7aac2808c4e85c97af05e45e4a24a3bc03e294b909f175e3cafa23d3baf7aa96b112e6461687d4c87b6bed34e3ee3bbec6e452d997f6cb7e3830acdffc08f5f5d52e575f1e1cc249101541f124b023b650430bafa2fb5ea6f1dd0e1cc8270a21c9830aa083cdd464cc685fbb0abcd5a92c45f67614fe53a12c49855284b3a436bfcb7591caa453956577ee9f0a5fd0ba608177035ad8e869080d8751de20fdcf75c314271cfd276bb768a9a93f554e74cd87e89288890c83c09574a967509d08104ee94365cfbe9dcd9e7ee135d383df9f71a03d27ff2282aa7b98fa893cd8ba7a2bb2a73678c365c34f79263193806257c4ac1285d5431504997a2afb641e65a6b453b0a22d6060b3b6ba5ff5a6da3d2ad38526366853ee601945f80d907bb846aa03d5eed27ca02ec6b6c2a0099096ed070a37b133bd1093ae6b13ef63c3a2424b02e8eb8ac110505dd37b4e0e1588b8366a75432db9d0d06c825708daba59aae9cbd4ca75e0
MT-APP-Version: 1.9.6
Sdk-Ver-Bb: V3.5.0_20260403.1_imaotai
content-type: application/json
Accept: application/json, text/javascript, */*; q=0.01
Content-Hh-Bb: 10e33ddf06731b3914edc463e80b1f5c
X-Requested-With: XMLHttpRequest
MT-Info: a3f9c2b8471de05f9b6c4e1287d5a9c1
User-Agent: Mozilla/5.0 (Linux; Android 12; 2201123C Build/SKQ1.211006.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/95.0.4638.74 Mobile Safari/537.36 moutaiapp/1.9.6 device-id/d22ac8c225fbdad138a287317b258535 BS-DVID/CV1z6ADnxGokMzTGFd-1XJEXM4uku4K-yg0YsqsFywHz_46-4Wv2GYDt8gv0djt96IP9zr3LyklfrYLeYtDarYQ
MT-K: 1777893752116
Origin: https://h5.moutai519.com.cn
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://h5.moutai519.com.cn/mt/item/smsp-detail?appConfig=2_1_2
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7
Cookie: MT-Token-Wap=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJtdCIsImV4cCI6MTc4MDM2MTk2NSwidXNlcklkIjoxMTk3MzM3NDEwLCJkZXZpY2VJZCI6ImNsaXBzX2NFRWtGaUlYSmtCeVFYSkRKUkIwUjNjV0lVUjhUeWxQS1JvdUdINUpjQT09IiwiaWF0IjoxNzc3NzY5OTY1fQ.Ej5gLah0FDO19pbdO2WzIHwYyasiGv7uAhUjQlzL7g8; MT-Device-ID-Wap=clips_cEEkFiIXJkByQXJDJRB0R3cWIUR8TylPKRouGH5JcA==; gdxidpyhxdE=MyuYse8gur39N%5CXBZ%5Cei5%2F07R6AOpH7A%2F0uuZY1EkVCYQD67Wu2a98TSEtuSpOldjk1h5TDmdXknMYC3ojc938dsbElNVSMmmTCp1DPW9OCQWvGKyTbo0VsC%2F6TNhpsiprY%5COQt3qin3rCbZN%2FhNuyvDP6TGEbHkhGV%5CWanAn2q8V0%5C2%3A1777826251350; _sdk_v_=V3.5.0_20260403.1_imaotai; _bs_device_id=bid-8867863987771-1518-ae4a; _d_u=432a1d531c62c4824f7203434b1d5a18e17c5577055af88aeb385d41d50e8ea8224ce18ff0479d10f76d8d8cb571c1fb45c4a1988b24171cf6ffdc8b7a802c31f04e71feaf35cce128630548ebd891510b6773b0b48da3a87ce2c2e622a6ded27f4770ac0a562b5adbe89495ddfc09b4d5f34e8f86e6141908308438fdc28618c0d0db3441885e75c309165af920f02d08f45085826e22c6080d4930ca5f77f8eaaec8658effecc3ebafa1ef0254aeea47aa15e726c8ad9b9ddfde0419b6618b8c54ded22dd4daa7c2266db61ddc3fd18e38301b82ab2f1a16d6913601545989a405a57928c675925b496307530d4ff6971265c3f0ce9811f8032aeb30bb8519
Content-Length: 423"#).unwrap();
    header.insert("x-csrf-token", "").unwrap();

    println!("{}", header);
    let mut req = AcReq::new()
        .with_fingerprint(fingerpirnt)
        // .with_alpn(ALPN::Http20)
        // .with_mtls(certs, key)
        .with_verify(true)
        .with_timeout(Timeout::new_same(10000, 2))
        .with_key_log("2.log")
        // .with_proxy(Proxy::new_http_plain("127.0.0.1", 10280))
        ;
    req.set_headers(header, false);

    let data = json::object! {"actParam":"salGYFt5S6bQg3QmZ92dY6bsH+8CAJ0R8kZwwurslmXbTh0epueTLDQriQRinhZlHxazFMfUEIr7IQzUxd3hjNAb2U/yYWciM2reBPdS+APR4IV9CE60Nb9n+Id++Pf4yYcdUEBJaTXQuMzNblj0M90JBJQbOG40L7GZCPdELGylgHK9C0F8BlSFNh80hSdRw2KmOJL2HAYyfuscHG0qTsHXECJ4+OHwBTcRt+dKDOhyl3LSAL5a8Eb3Ht1vLgleDKmr0SzyDEIVOJuSPW23F4Fmq7NPIOnPY8hL5XL3ewpBpgGWj53vu2SVi27sTRioopNhjW6J2SOQyUsHFj60EpCbMwh6++NkGum/ltUZ1OHpN7psICQQXb9FDuak/2ytffZiKbZcLWgiF+FuuB2ofXV77NfUhTTr7xO6S/J32rI="};
    // req.set_headers_json(headers).unwrap();
    // req.set_url(url).await.unwrap();
    // req.set_json(data);

    let url = "https://220.167.102.112/xhr/front/trade/priority/rushPurchase/hot/branch/one";
    let res = req.post(url.sni("h5.moutai519.com.cn"), data).await.unwrap();
    // let res=req.post("https://shangoue.meituan.com",None).await.unwrap();
    println!("{}", res.header());
    if res.header().get("connection").unwrap().to_string().contains("close") {
        req.stream_mut().async_shutdown().await.unwrap();
    }
    req.stream_mut().async_shutdown().await.unwrap();
    println!("{}", res.text().unwrap());
    sleep(Duration::from_hours(12)).await;
    //
    return;
    let mut timeout = Timeout::longer();
    timeout.set_handle_times(1);
    let fingerprint = Fingerprint::from_hex_all("16030105b7010005b303030197f07eba2317b09411ccca32c3ca4520c7a4d427d4617d3219e9173c21567b207ef647003b4151c1a8f1f4e72b3e2821b98a5af7d7f7f1cb9912965dd8be2e620014130213011303c02cc02bcca9c030c02fcca800ff01000556000d0016001405030403060308070806080508040601050104010017000000230000000000160014000011736730332e636b636c6f75642e696e666f000500050100000000000a000a000811ec001d00170018002d00020101002b00050403040303000b00020100003304ea04e811ec04c0f0a71f3c99832eb733b81ba2c01c0807b94c4877963bd3ae5d08af1d02cf0f719337f948cf5938421c52ae8baacaacbffe32cc91abaa8f89a2f5002f7029102a02ae330255eeda21a8a6517ee872f646273b97ad094c6bde77a9829c6eee7ab9a7799823c3a7aed931dda20cbb2c45ac58133ac4351c38438d4b5f2dbac976b8a955d153bab3769657bc07f51f0715ab9e561b12496aa02238ed2b32816446ba367074930d8efb0cabd48387127d5bca9bada07acb29c9fe1958c6e0cf2b6b53365626898c32fcf23b3eb11b339abbeff313c8097263382d42b090d8765bd262a3b63a45dbf5c04ab94417a35dad713293d1991802ca67da9ccc527f6ce629df08a073b4193e372898d23f04c14bc7053e1112707f2c187876b98ca91aaafc0bcd61806b211d99e60d1eb8bdcefb04bba3a0e4ca1c7d4945c7e5567aa5025b57cca2e80991892debf11a4b067136581d3ed59912460be9f24941c34e88d4661cb09f464097b9b573e8d349871b0db3a513e3c61983a5c5193850f400226ed30c17a6b615b077564647ae6ab09f3cc5cbc74cc78990f20311f2eb37f9e077215098c64335a1e25fa9876f3593ccb9004413731cef6c09472b507d4395b23a242f723843601bbfe4c330ebce51da911967a85ad1a5792999341a117c407c86a49461887828b818bad9c600db50a2ca4ac86199394031afe9a28677631ce49785cc782818a29a14c2375c4aa79998e241207cbc603a32b142843b73d52ec1b92f7b1aca57817ce5d4109ee8734617c8e69147ee59252838a1639276adba5672049a661146f7039dcb18a93c0b634c87cd51fc2a187935bb5062b4d0322596c223a49c052bc8fb12acfeeb428002aa62d660016b9460016f28984a175890a5d67c74466d44117184d219ccc27d3d551de595111f2b185e929e324954a3568e6dd63e10ab4e5947185df02f648a9a8af436516aa813679b787b807b003245a796795cb91453a8482283fa66aa66a3837f4a6ee2d2340962a2cc9c4e62c6033947605ce72e0046aab962871c9850bbeb0d8d14c47391bab9a59c3e35c1e47ccb8a0c8ee855cc99ec64a993579d993f9e12711d16aa61aa2a915c0baa6acf3df4c9521a4dcd4c002ec56bfb4c7b5116ab06f1859d857c939ca29fcb6e23c93d6975ca6f49a6c0d1a5246bc8894893914122c3cb3220939e3aa916358360386ba76603ab9440916bf585c5537f26b77f2e7459bc707ee47527b54b239bcb58254288e75a927673ae74050eb35280b16369aacb85da861302f19fec1c7ac17185367b6a7c773f6b1abc0bb685f4cc518153c3a76c4d89795444f493adf373b40a92e9f18eaf224d90d48f0e6a7213a2b860a36f585b84ca24a33ce72014ec43dc046b0612922eb457a24049655a664072b2832314a6f2ccadf7b862692069d269cc62351bd279d683068327b668065084890c3f3c04d959adf2903ad1424a9a60b1cf3aa24ea81dbcf71ed8c82bd3cc271dda799d2b0d2f208163bc7f8b66a48db9a4aed10eb705690734cfa575b4deeca83619524aeb963e9c2ee81c7f51d91efe0a1f2f79a332b02bbe8a55e8625025f387b5a27982a78296f4c172720606073b2ada9bb924a44b941e81f90811ad449914919c6dd9a9562c2a99c5833bc010d91e65fe3ac6022cd7e274d3e9a787bbef8ec3507c25b8fa29475e235fda8ac4a6af9f31001d00203ac6022cd7e274d3e9a787bbef8ec3507c25b8fa29475e235fda8ac4a6af9f311603030046100000424104ff635373fbbfbc37444a2026372f57fd06c5205bacfe32b61261a9d29bf1fca57f91ef22cb2ba46af8cf9ae7c3123f56634099af297dcd30835cd81664005fb9140303000101", "2f-o7ffnfc-j2f7q7n-k7ffnfc-m423p26-k").unwrap();


    // let fingerprint = Fingerprint::from_ja3("771,4866-4867-4865-49196-49200-49195-49199-52393-52392-49188-49192-49187-49191-159-158-107-103-255,0-11-10-16-22-23-49-13-43-45-51-21,29-23-30-25-24-256-257-258-259-260,0-1-2", "2f-o7ffnfc-j2f7q7n-k7ffnfc-m423p26-k").unwrap();
    // let fingerprint = Fingerprint::from_ja4("t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01_0403,0804,0401,0503,0805,0501,0806,0601", "2f-o7ffnfc-j2f7q7n-k7ffnfc-m423p26-k").unwrap();
    // let fingerprint = Fingerprint::random("").unwrap();
    //
    // return;
    // let fingerprint = Fingerprint::from_hex_all("16030105b7010005b303030197f07eba2317b09411ccca32c3ca4520c7a4d427d4617d3219e9173c21567b207ef647003b4151c1a8f1f4e72b3e2821b98a5af7d7f7f1cb9912965dd8be2e620014130213011303c02cc02bcca9c030c02fcca800ff01000556000d0016001405030403060308070806080508040601050104010017000000230000000000160014000011736730332e636b636c6f75642e696e666f000500050100000000000a000a000811ec001d00170018002d00020101002b00050403040303000b00020100003304ea04e811ec04c0f0a71f3c99832eb733b81ba2c01c0807b94c4877963bd3ae5d08af1d02cf0f719337f948cf5938421c52ae8baacaacbffe32cc91abaa8f89a2f5002f7029102a02ae330255eeda21a8a6517ee872f646273b97ad094c6bde77a9829c6eee7ab9a7799823c3a7aed931dda20cbb2c45ac58133ac4351c38438d4b5f2dbac976b8a955d153bab3769657bc07f51f0715ab9e561b12496aa02238ed2b32816446ba367074930d8efb0cabd48387127d5bca9bada07acb29c9fe1958c6e0cf2b6b53365626898c32fcf23b3eb11b339abbeff313c8097263382d42b090d8765bd262a3b63a45dbf5c04ab94417a35dad713293d1991802ca67da9ccc527f6ce629df08a073b4193e372898d23f04c14bc7053e1112707f2c187876b98ca91aaafc0bcd61806b211d99e60d1eb8bdcefb04bba3a0e4ca1c7d4945c7e5567aa5025b57cca2e80991892debf11a4b067136581d3ed59912460be9f24941c34e88d4661cb09f464097b9b573e8d349871b0db3a513e3c61983a5c5193850f400226ed30c17a6b615b077564647ae6ab09f3cc5cbc74cc78990f20311f2eb37f9e077215098c64335a1e25fa9876f3593ccb9004413731cef6c09472b507d4395b23a242f723843601bbfe4c330ebce51da911967a85ad1a5792999341a117c407c86a49461887828b818bad9c600db50a2ca4ac86199394031afe9a28677631ce49785cc782818a29a14c2375c4aa79998e241207cbc603a32b142843b73d52ec1b92f7b1aca57817ce5d4109ee8734617c8e69147ee59252838a1639276adba5672049a661146f7039dcb18a93c0b634c87cd51fc2a187935bb5062b4d0322596c223a49c052bc8fb12acfeeb428002aa62d660016b9460016f28984a175890a5d67c74466d44117184d219ccc27d3d551de595111f2b185e929e324954a3568e6dd63e10ab4e5947185df02f648a9a8af436516aa813679b787b807b003245a796795cb91453a8482283fa66aa66a3837f4a6ee2d2340962a2cc9c4e62c6033947605ce72e0046aab962871c9850bbeb0d8d14c47391bab9a59c3e35c1e47ccb8a0c8ee855cc99ec64a993579d993f9e12711d16aa61aa2a915c0baa6acf3df4c9521a4dcd4c002ec56bfb4c7b5116ab06f1859d857c939ca29fcb6e23c93d6975ca6f49a6c0d1a5246bc8894893914122c3cb3220939e3aa916358360386ba76603ab9440916bf585c5537f26b77f2e7459bc707ee47527b54b239bcb58254288e75a927673ae74050eb35280b16369aacb85da861302f19fec1c7ac17185367b6a7c773f6b1abc0bb685f4cc518153c3a76c4d89795444f493adf373b40a92e9f18eaf224d90d48f0e6a7213a2b860a36f585b84ca24a33ce72014ec43dc046b0612922eb457a24049655a664072b2832314a6f2ccadf7b862692069d269cc62351bd279d683068327b668065084890c3f3c04d959adf2903ad1424a9a60b1cf3aa24ea81dbcf71ed8c82bd3cc271dda799d2b0d2f208163bc7f8b66a48db9a4aed10eb705690734cfa575b4deeca83619524aeb963e9c2ee81c7f51d91efe0a1f2f79a332b02bbe8a55e8625025f387b5a27982a78296f4c172720606073b2ada9bb924a44b941e81f90811ad449914919c6dd9a9562c2a99c5833bc010d91e65fe3ac6022cd7e274d3e9a787bbef8ec3507c25b8fa29475e235fda8ac4a6af9f31001d00203ac6022cd7e274d3e9a787bbef8ec3507c25b8fa29475e235fda8ac4a6af9f311603030046100000424104ff635373fbbfbc37444a2026372f57fd06c5205bacfe32b61261a9d29bf1fca57f91ef22cb2ba46af8cf9ae7c3123f56634099af297dcd30835cd81664005fb9140303000101", "2f-o7ffnfc-j2f7q7n-k7ffnfc-m423p26-k").unwrap();
    // let fingerprint = Fingerprint::random("516k711n1c-j592g6.1k711n1c-j5d6a561k").unwrap();
    // let certs = Certificate::from_pem_file("/home/xl/1/client.crt").unwrap();
    // let key = RsaKey::from_pri_pem_file("/home/xl/1/client.key").unwrap();
    let mut req = AcReq::new()
        // .with_fingerprint(fingerprint)
        .with_alpn(ALPN::Http20)
        .with_timeout(timeout)
        .with_verify(true)
        .with_key_log("2.log")
        // .with_mtls(certs, key)
        // .with_proxy(Proxy::try_from("http://127.0.0.1:10240").unwrap())
        ;
    let headers = json::object! {
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
        // "cookie":"_EDGE_V=1; MUIDB=184C10AD397866DF1A1607B038566708; MUID=184C10AD397866DF1A1607B038566708; _UR=QS=0&TQS=0&Pn=0; BFBUSR=BFBHP=0; MUIDB=184C10AD397866DF1A1607B038566708; SRCHD=AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF&AF=NOFORM; SRCHUID=V=2&GUID=EB7B9E5DE58F4D5690F6904732C24C7B&dmnchg=1; USRLOC=HS&ELOC=LAT=23.384721755981445|LON=113.44195556640625|N=%E7%99%BD%E4%BA%91%E5%8C%BA%EF%BC%8C%E5%B9%BF%E4%B8%9C%E7%9C%81|ELT=4|&HS=1; _RwBf=r&r&r&r&r=0&ilt=10&ihpd=5&ispd=3&rc=12&rb=0&rg=200&pc=12&mtu=0&rbb=0&clo=0&v=8&l=2026-03-15T07:00:00.0000000Z&lft=0001-01-01T00:00:00.0000000&aof=0&ard=0001-01-01T00:00:00.0000000&rwdbt=0&rwflt=0&rwaul2=0&g=&o=2&p=&c=&t=0&s=0001-01-01T00:00:00.0000000+00:00&ts=2026-03-15T14:03:35.7211444+00:00&rwred=0&wls=&wlb=&wle=&ccp=&cpt=&lka=0&lkt=0&aad=0&TH=&cid=0&gb=; SRCHUSR=DOB&DS&DS&DS&DS&DS=1&DOB=20260315; _EDGE_S=SID=357AA105805E678827ACB618817066E6; _SS=SID=357AA105805E678827ACB618817066E6; _HPVN=CS=eyJQbiI6eyJDbiI6MSwiU3QiOjAsIlFzIjowLCJQcm9kIjoiUCJ9LCJTYyI6eyJDbiI6MSwiU3QiOjAsIlFzIjowLCJQcm9kIjoiSCJ9LCJReiI6eyJDbiI6MSwiU3QiOjAsIlFzIjowLCJQcm9kIjoiVCJ9LCJBcCI6dHJ1ZSwiTXV0ZSI6dHJ1ZSwiTGFkIjoiMjAyNi0wMy0xNVQwMDowMDowMFoiLCJJb3RkIjowLCJHd2IiOjAsIlRucyI6MCwiRGZ0IjpudWxsLCJNdnMiOjAsIkZsdCI6MCwiSW1wIjozMCwiVG9ibiI6MH0=; SRCHHPGUSR=SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&V&SRCHLANG&SRCHLANG&SRCHLANG&V&SRCHLANG&SRCHLANG=zh-Hans&PREFCOL=0&BRW=NOTP&BRH=M&CW=150&CH=769&SCW=150&SCH=769&DPR=1.0&UTC=480&HV=1773588648&HVE=CfDJ8HAK7eZCYw5BifHFeUHnkJGC6_lT8f9GeruXx8zjPXuk-5GHkofYMoFErMkT8CTKKKsSt5O2HyGmjLyCEXbEREUmwCd8ZBlYMLSDZu1wZ-EI1LDuyIiI1tkP6Usyicm601qX3aJVYqVWUBn-t6h0ZWLiftm4aS627xFj1fE5PD-85i7BWTkhqG0uvaYzuSgB2A&BZA=0&PRVCW=150&PRVCH=769&B=0&EXLTT=7&V=CfDJ8HAK7eZCYw5BifHFeUHnkJGijeRjCoaCMaAnmznMvdEg2GXY8647Wb-7wnHNpePKXRO6KRQ_0cQc-onivd35uV-p-4g0MB0V_Z1ZpW-QSJe9zbPUG-Ks-kQMjzEl6GlLo6N0ciP51vkQdR-P-lCUH58&PR=1"
    };
    req.set_headers_json(headers).unwrap();
    // let data = json::object! {
    //     "body":"spLabel=false&clueLabel=false&id=24055967626&spTitle=pre_data6&productNameSupplement=&description=&picContent=&spPicContentSwitch=1&shippingTimeX=-&skus=%5B%7B%22id%22%3A44382959111%2C%22spec%22%3A%22455%22%2C%22price%22%3A10%2C%22unit%22%3A%22%E4%BB%BD%22%2C%22stock%22%3A1%2C%22weight%22%3A0%2C%22weightUnit%22%3A%22%E5%85%8B%28g%29%22%2C%22ladderPrice%22%3A0%2C%22ladderNum%22%3A1%2C%22upcCode%22%3A%22211102884294%22%2C%22upc%22%3A%22211102884294%22%2C%22sourceFoodCode%22%3A%22a2640479882013848866%22%2C%22skuCode%22%3A%22a2640479882013848866%22%2C%22shelfNum%22%3A%22%22%2C%22minOrderCount%22%3A1%2C%22skuAttrs%22%3A%5B%5D%2C%22oriPrice%22%3A0%2C%22skipUpcImg%22%3A%22%22%2C%22commonProperty%22%3Anull%7D%5D&attrList=%5B%5D&picture=http%3A%2F%2Fp0.meituan.net%2Fscproduct%2F18a930e5f9b95f8fcedd9ee4ff220cd3148954.jpg&labels=%5B%7B%22group_id%22%3A43%2C%22sub_attr%22%3A0%7D%5D&isSp=0&categoryId=400000364&categoryPath=200001013%2C200001014%2C400000364&releaseType=0&tagList=%5B%7B%22tagId%22%3A1377205822%2C%22tagName%22%3A%22%E6%9C%AA%E5%88%86%E7%B1%BB%22%7D%5D&limitSale=%7B%22limitSale%22%3Afalse%2C%22begin%22%3A%22%22%2C%22end%22%3A%22%22%2C%22type%22%3A1%2C%22frequency%22%3A1%2C%22count%22%3A0%7D&categoryAttrMap=%7B%221200000003%22%3A%7B%22attrId%22%3A1200000003%2C%22attrName%22%3A%22%E5%89%82%E5%9E%8B%22%2C%22attrType%22%3A3%2C%22inputType%22%3A1%2C%22sequence%22%3A9%2C%22isRequired%22%3A0%2C%22valueList%22%3A%5B%5D%7D%2C%221200000005%22%3A%7B%22attrId%22%3A1200000005%2C%22attrName%22%3A%22%E6%B3%A8%E6%84%8F%E4%BA%8B%E9%A1%B9%22%2C%22attrType%22%3A3%2C%22inputType%22%3A3%2C%22sequence%22%3A16%2C%22isRequired%22%3A0%2C%22valueList%22%3A%5B%7B%22value%22%3A%22%22%2C%22valueIdPath%22%3A%22%22%2C%22valuePath%22%3A%22%22%2C%22selected%22%3A1%7D%5D%7D%2C%221200000011%22%3A%7B%22attrId%22%3A1200000011%2C%22attrName%22%3A%22%E9%80%82%E5%AE%9C%E4%BA%BA%E7%BE%A4%22%2C%22attrType%22%3A3%2C%22inputType%22%3A3%2C%22sequence%22%3A12%2C%22isRequired%22%3A0%2C%22valueList%22%3A%5B%7B%22value%22%3A%22%22%2C%22valueIdPath%22%3A%22%22%2C%22valuePath%22%3A%22%22%2C%22selected%22%3A1%7D%5D%7D%2C%221200000012%22%3A%7B%22attrId%22%3A1200000012%2C%22attrName%22%3A%22%E6%88%90%E5%88%86%22%2C%22attrType%22%3A3%2C%22inputType%22%3A3%2C%22sequence%22%3A7%2C%22isRequired%22%3A0%2C%22valueList%22%3A%5B%7B%22value%22%3A%22%22%2C%22valueIdPath%22%3A%22%22%2C%22valuePath%22%3A%22%22%2C%22selected%22%3A1%7D%5D%7D%2C%221200000014%22%3A%7B%22attrId%22%3A1200000014%2C%22attrName%22%3A%22%E8%B4%AE%E8%97%8F%22%2C%22attrType%22%3A3%2C%22inputType%22%3A3%2C%22sequence%22%3A14%2C%22isRequired%22%3A1%2C%22valueList%22%3A%5B%7B%22value%22%3A%22%E5%B7%B2%22%2C%22valueIdPath%22%3A%22%22%2C%22valuePath%22%3A%22%22%2C%22selected%22%3A1%7D%5D%7D%2C%221200000015%22%3A%7B%22attrId%22%3A1200000015%2C%22attrName%22%3A%22%E6%B8%A9%E9%A6%A8%E6%8F%90%E7%A4%BA%22%2C%22attrType%22%3A3%2C%22inputType%22%3A3%2C%22sequence%22%3A19%2C%22isRequired%22%3A0%2C%22valueList%22%3A%5B%7B%22value%22%3A%221.%E2%80%9C%E5%9B%BD%E5%AE%B6%E8%8D%AF%E7%9B%91%E5%B1%80%E6%8F%90%E7%A4%BA%E6%82%A8%EF%BC%9A%E8%AF%B7%E6%AD%A3%E7%A1%AE%E8%AE%A4%E8%AF%86%E5%8C%96%E5%A6%86%E5%93%81%E5%8A%9F%E6%95%88%EF%BC%8C%E5%8C%96%E5%A6%86%E5%93%81%E4%B8%8D%E8%83%BD%E6%9B%BF%E4%BB%A3%E8%8D%AF%E5%93%81%EF%BC%8C%E4%B8%8D%E8%83%BD%E6%B2%BB%E7%96%97%E7%9A%AE%E8%82%A4%E7%97%85%E7%AD%89%E7%96%BE%E7%97%85%E2%80%9D%EF%BC%8C%E6%8F%90%E9%86%92%E5%B9%BF%E5%A4%A7%E6%B6%88%E8%B4%B9%E8%80%85%E9%98%B2%E8%8C%83%E5%8C%96%E5%A6%86%E5%93%81%E6%B6%88%E8%B4%B9%E9%A3%8E%E9%99%A9%EF%BC%9B2.%E7%94%B1%E4%BA%8E%E5%8E%82%E5%AE%B6%E4%B8%8D%E5%AE%9A%E6%9C%9F%E6%9B%B4%E6%8D%A2%E4%BA%A7%E5%93%81%E5%8C%85%E8%A3%85%EF%BC%8C%E5%A6%82%E9%81%87%E6%96%B0%E5%8C%85%E8%A3%85%E4%B8%8A%E5%B8%82%E5%8F%AF%E8%83%BD%E5%AD%98%E5%9C%A8%E6%9B%B4%E6%96%B0%E6%BB%9E%E5%90%8E%EF%BC%8C%E8%AF%B7%E4%BB%A5%E6%94%B6%E5%88%B0%E7%9A%84%E5%AE%9E%E8%B4%A7%E5%8C%85%E8%A3%85%E4%B8%BA%E5%87%86%EF%BC%81%22%2C%22valueIdPath%22%3A%22%22%2C%22valuePath%22%3A%22%22%2C%22selected%22%3A1%7D%5D%7D%2C%221200000017%22%3A%7B%22attrId%22%3A1200000017%2C%22attrName%22%3A%22%E7%94%A8%E6%B3%95%E7%94%A8%E9%87%8F%22%2C%22attrType%22%3A3%2C%22inputType%22%3A3%2C%22sequence%22%3A13%2C%22isRequired%22%3A1%2C%22valueList%22%3A%5B%7B%22value%22%3A%22%E5%B7%B2%22%2C%22valueIdPath%22%3A%22%22%2C%22valuePath%22%3A%22%22%2C%22selected%22%3A1%7D%5D%7D%2C%221200000018%22%3A%7B%22attrId%22%3A1200000018%2C%22attrName%22%3A%22%E7%94%9F%E4%BA%A7%E4%BC%81%E4%B8%9A%22%2C%22attrType%22%3A3%2C%22inputType%22%3A3%2C%22sequence%22%3A5%2C%22isRequired%22%3A1%2C%22valueList%22%3A%5B%7B%22value%22%3A%22%E5%B7%B2%22%2C%22valueIdPath%22%3A%22%22%2C%22valuePath%22%3A%22%22%2C%22selected%22%3A1%7D%5D%7D%2C%221200000073%22%3A%7B%22attrId%22%3A1200000073%2C%22attrName%22%3A%22%E9%80%82%E7%94%A8%E8%8C%83%E5%9B%B4%22%2C%22attrType%22%3A3%2C%22inputType%22%3A3%2C%22sequence%22%3A11%2C%22isRequired%22%3A0%2C%22valueList%22%3A%5B%7B%22value%22%3A%22%22%2C%22valueIdPath%22%3A%22%22%2C%22valuePath%22%3A%22%22%2C%22selected%22%3A1%7D%5D%7D%2C%221200000080%22%3A%7B%22attrId%22%3A1200000080%2C%22attrName%22%3A%22%E6%9C%89%E6%95%88%E6%9C%9F%22%2C%22attrType%22%3A3%2C%22inputType%22%3A3%2C%22sequence%22%3A15%2C%22isRequired%22%3A1%2C%22valueList%22%3A%5B%7B%22value%22%3A%22%E5%B7%B2%22%2C%22valueIdPath%22%3A%22%22%2C%22valuePath%22%3A%22%22%2C%22selected%22%3A1%7D%5D%7D%2C%221200000085%22%3A%7B%22attrId%22%3A1200000085%2C%22attrName%22%3A%22%E4%BA%A7%E5%9C%B0%E7%B1%BB%E5%9E%8B%22%2C%22attrType%22%3A3%2C%22inputType%22%3A1%2C%22sequence%22%3A6%2C%22isRequired%22%3A1%2C%22valueList%22%3A%5B%7B%22valueId%22%3A1300000003%2C%22value%22%3A%22%E5%9B%BD%E4%BA%A7%22%2C%22valueIdPath%22%3A%221300000003%22%2C%22valuePath%22%3A%221%22%2C%22sequence%22%3A1%2C%22selected%22%3A1%7D%5D%7D%2C%221200000086%22%3A%7B%22attrId%22%3A1200000086%2C%22attrName%22%3A%22%E6%89%B9%E5%87%86%E6%96%87%E5%8F%B7%22%2C%22attrType%22%3A1%2C%22inputType%22%3A3%2C%22sequence%22%3A4%2C%22isRequired%22%3A1%2C%22valueList%22%3A%5B%7B%22value%22%3A%22%E5%B7%B2%22%2C%22valueIdPath%22%3A%22%22%2C%22valuePath%22%3A%22%22%2C%22selected%22%3A1%7D%5D%7D%2C%221200000088%22%3A%7B%22attrId%22%3A1200000088%2C%22attrName%22%3A%22%E5%93%81%E7%89%8C%22%2C%22attrType%22%3A1%2C%22inputType%22%3A1%2C%22sequence%22%3A2%2C%22isRequired%22%3A0%2C%22valueList%22%3A%5B%5D%7D%2C%221200000159%22%3A%7B%22attrId%22%3A1200000159%2C%22attrName%22%3A%22%E4%BA%A7%E5%93%81%E5%90%8D%E7%A7%B0%22%2C%22attrType%22%3A1%2C%22inputType%22%3A3%2C%22sequence%22%3A1%2C%22isRequired%22%3A1%2C%22valueList%22%3A%5B%7B%22value%22%3A%22%E5%B7%B2%22%2C%22valueIdPath%22%3A%22%22%2C%22valuePath%22%3A%22%22%2C%22selected%22%3A1%7D%5D%7D%2C%221200000251%22%3A%7B%22attrId%22%3A1200000251%2C%22attrName%22%3A%22%E4%BA%A7%E5%93%81%E5%8A%9F%E6%95%88%22%2C%22attrType%22%3A3%2C%22inputType%22%3A3%2C%22sequence%22%3A10%2C%22isRequired%22%3A0%2C%22valueList%22%3A%5B%7B%22value%22%3A%22%22%2C%22valueIdPath%22%3A%22%22%2C%22valuePath%22%3A%22%22%2C%22selected%22%3A1%7D%5D%7D%2C%221200004423%22%3A%7B%22attrId%22%3A1200004423%2C%22attrName%22%3A%22%E5%95%86%E6%A0%87%22%2C%22attrType%22%3A1%2C%22inputType%22%3A1%2C%22sequence%22%3A3%2C%22isRequired%22%3A0%2C%22valueList%22%3A%5B%5D%7D%2C%221200004527%22%3A%7B%22attrId%22%3A1200004527%2C%22attrName%22%3A%22%E5%84%BF%E7%AB%A5%E5%8C%96%E5%A6%86%E5%93%81%22%2C%22attrType%22%3A3%2C%22inputType%22%3A1%2C%22sequence%22%3A18%2C%22isRequired%22%3A0%2C%22valueList%22%3A%5B%5D%7D%2C%221200189598%22%3A%7B%22attrId%22%3A1200189598%2C%22attrName%22%3A%22%E6%89%A7%E8%A1%8C%E6%A0%87%E5%87%86%E6%96%87%E5%8F%B7%22%2C%22attrType%22%3A3%2C%22inputType%22%3A3%2C%22sequence%22%3A18%2C%22isRequired%22%3A0%2C%22valueList%22%3A%5B%7B%22value%22%3A%22%22%2C%22valueIdPath%22%3A%22%22%2C%22valuePath%22%3A%22%22%2C%22selected%22%3A1%7D%5D%7D%7D&spuSaleAttrMap=%7B%7D&upcImage=&sellStatus=1&marketingPicture=&marketingPicList=&industryPics=%5B%7B%22type%22%3A1%2C%22quoteSwitch%22%3A0%7D%2C%7B%22type%22%3A2%2C%22quoteSwitch%22%3A0%7D%5D&wmPoiId=31309015&skipAudit=false&validType=0&missingRequiredInfo=false&auditStatus=0&useSuggestCategory=false&auditScene=0&saveType=1&auditSource=1&spVideoStatus=0&checkActivitySkuModify=true&hsCodeId=",
    //     "method":"POST",
    //     "cookie":r#"_lxsdk_cuid=1999098642bc8-03c78c52e8aedd-76574611-384000-1999098642c4; _lxsdk=1999098642bc8-03c78c52e8aedd-76574611-384000-1999098642c4; e_b_id_352126=4b43997da8f5f5aa8082a019a6cdf04e; uuid_update=true; acctId=267433045; token=0cpJblTnhR5bQFB_39b9g2SSwbXnyTWLAniQgW--LYfs*; brandId=-1; wmPoiId=31309015; isOfflineSelfOpen=2; city_id=0; isChain=0; existBrandPoi=true; ignore_set_router_proxy=false; region_id=0; region_version=0; newCategory=true; bsid=EyePQTksNOTzBax0Jj0WXN7afqoa0oHmoMBZsTRn1yHXGkItD0ShP6FUcrSeokuN3CQGi7ftajaZxvQ9Vmoqdw; device_uuid=!b0cfb761-8530-4aad-9d72-7f85b01606ed; _gw_ab_call_37616_150=TRUE; _gw_ab_37616_150=851; logistics_support=1; cityId=440100; provinceId=440000; city_location_id=610100; location_id=610103; account_businesstype=1; single_poi_businesstype=1; accountAllPoiBusinessType=1; acct_id=267433045; acct_name=mt838377du; poi_id=31309015; account_second_type=200; poi_first_category_id=22; poi_second_category_id=4012; pushToken=0cpJblTnhR5bQFB_39b9g2SSwbXnyTWLAniQgW--LYfs*; isNewCome=1; set_info={"wmPoiId":31309015,"region_id":"1000610100","region_version":1766133001}; pharmacistAccount=0; wpush_server_url=wss://wpush.meituan.com; shopCategory=medicine; com.sankuai.yiyao.shangjia.main_strategy=; cacheTimeMark=2026-01-18; WEBDFPID=z8yy33552xwy586vz4x1x5xw0y1832z98000901270247958w8y12yy6-1768794670395-1759067529980SMCUUEKa12a6b8169ee7736639f3ec62dbf984b1665; utm_source_rg=AM%2566AyTyT%25284; yy-epassport-accessToken=EyePQTksNOTzBax0Jj0WXN7afqoa0oHmoMBZsTRn1yHXGkItD0ShP6FUcrSeokuN3CQGi7ftajaZxvQ9Vmoqdw; com.sankuai.yiyao.eproduct.manager_strategy=; logan_session_token=zjnxg3h69dimc8jf1c59; _lxsdk_s=19bcf3a66bb-504-7a4-cd5%7C%7C201"#,
    //     "url":"https://yiyao.meituan.com/reuse/health/product/retail/w/uniSave?yodaReady=h5&csecplatform=4&csecversion=4.2.0",
    //     "type":"hs1.6"
    // };
    // req.header_mut().set_authorization("Upy9fDyueOXiEbON0vRXimw/tlHO5QHs+IV75wUbSzZngY0oLn1wJpQ00TnW1Cihu1UUnDUvVg4y9FggZe9nlMYfUxbwWBKP27EmkCEmyrxnrlc5inWEeK3OXKwUhhfc").unwrap();
    // let url = "https://testapi.xllgl.top:3453/v1/api/mtgsig";
    // req.set_url(url).await.unwrap();
    // req.set_json(data);
    // let res = req.post().await.unwrap().text().unwrap();
    // println!("{}",res);
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
    // req.set_url("http://zwfw.hubei.gov.cn/web/user/uias_login.do?appCode=hbzwfw&gotoUrl=http%3A%2F%2Fzwfw.hubei.gov.cn%2Fwebview%2Fgrkj%2Fwelcome.html&p01=").await.unwrap();
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
    // req.set_proxy(Proxy::new_socks5("127.0.0.1", 10279));
    // req.set_url("https://m.baidu.com").await.unwrap();
    // req.set_url("https://www.sephora.com/").await.unwrap();
    // req.set_url("https://doc.rust-lang.org/").await.unwrap();
    // req.set_url("https://tls.123408.xyz/api/clean").await.unwrap();
    // req.set_url("https://mcs-mimp-web.sf-express.com/mcs-mimp/sendValidCode").await.unwrap()
    // req.set_url("https://jetstar.com").await.unwrap();
    // req.set_url("https://127.0.0.1:8000").await.unwrap();
    // req.set_auto_redirect(false);
    // req.set_url("https://oauth.hubei.gov.cn:8443/").await.unwrap();
    req.set_auto_redirect(false);
    // let res = req.get("https://dns.alidns.com/resolve?name=crypto.cloudflare.com&type=HTTPS", None).await.unwrap();
    // let res=req.get("https://www.link114.cn/",None).await.unwrap();
    // let res = req.get("https://www.bing.com".params(json::object! {}), vec![0u8; 0].ty(Application::Json)).await.unwrap();
    // let res = req.get("https://117.89.181.21".sni("m.sogou.com"), None).await.unwrap();
    // let res=req.get("https://oauth.hubei.gov.cn:8443/",None).await.unwrap();
    let res = req.get("https://zwfw.hubei.gov.cn/web/user/uias_login.do?appCode=hbzwfw&gotoUrl=https%3A%2F%2Fzwfw.hubei.gov.cn%2Fwebview%2Fgrkj%2Fwelcome.html&p01=", None).await.unwrap();
    println!("{}", res.header());
    // println!("{}", res.json().unwrap().pretty())
    // println!("{:#?}", req.header().cookies());
    // println!("{}",res.text().unwrap());
    // req.set_url("https://m.so.com").await.unwrap();
    // req.set_url("https://im.jinritemai.com/").await.unwrap();
    // req.set_auto_redirect(false);
    // req.set_url("https://cn.bing.com/AS/Suggestions?pt=page.home&qry=&csr=1&pths=1&zis=1&pf=1&cvid=AFEA02EAF9E449A99970476597AE6CED").await.unwrap();
    // req.set_text("sfssdfsfsdfdf");
    // println!("{:?}",String::from_utf8(fs::read("/home/xl/1/ca.crt").unwrap()).unwrap());
    // let data = json::object! {"test_key":"test_value"};
    // let file = HttpFile::new_bytes_data(data, fs::read("/home/xl/1/ca.crt").unwrap());
    // req.set_files(file).unwrap();
    // req.set_data(data);
    // println!("{}", req.h1_raw_string().unwrap());
    // let res = req.get().await.unwrap();
    // println!("{} {:#?}", res.header().status(), req.header().cookies());
    // let params = json::object! {
    //     format:"{\\json",
    //     ecount:20,
    //     efirst:0
    // };
    // let url = "https://cn.bing.com/hp/api/v1/carousel".to_string();
    // // println!("{}", url);
    // let res = req.get(url.params(params), None).await.unwrap();
    // req.set_url("https://cn.bing.com/notifications/render?bnptrigger=%7B%22PartnerId%22%3A%22HomePage%22%2C%22IID%22%3A%22Bnp%22%2C%22Attributes%22%3A%7B%22RawRequestURL%22%3A%22%2F%22%7D%7D&IG=AFEA02EAF9E449A99970476597AE6CED&IID=Bnp").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/web/xlsc.aspx?dl=1&f=8").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/hp/api/model").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/sa/simg/favicon-trans-bg-blue-mg-png.png").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/web/xlsc.aspx?dl=1&f=8").await.unwrap();
    // let res = req.get().await.unwrap();
    // let res = req.get().await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/AS/Suggestions?pt=page.home&qry=&csr=1&pths=1&zis=1&pf=1&cvid=AFEA02EAF9E449A99970476597AE6CED").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/hp/api/v1/carousel?&format=json&ecount=20&efirst=0&&").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/notifications/render?bnptrigger=%7B%22PartnerId%22%3A%22HomePage%22%2C%22IID%22%3A%22Bnp%22%2C%22Attributes%22%3A%7B%22RawRequestURL%22%3A%22%2F%22%7D%7D&IG=AFEA02EAF9E449A99970476597AE6CED&IID=Bnp").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/web/xlsc.aspx?dl=1&f=8").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/hp/api/model").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/sa/simg/favicon-trans-bg-blue-mg-png.png").await.unwrap();
    // let res = req.get().await.unwrap();
    // req.set_url("https://cn.bing.com/web/xlsc.aspx?dl=1&f=8").await.unwrap();
    // let res = req.get().await.unwrap();
    // let res = req.get().await.unwrap();
    // let res = req.get().await.unwrap();
    // println!("{}", res.header());
}