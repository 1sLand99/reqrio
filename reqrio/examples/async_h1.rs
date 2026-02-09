use reqrio::*;

#[tokio::main]
async fn main() {
    // let mut fingerprint = Fingerprint::from_hex_all("16030105d8010005d403035029891305da2c94b8ac665e073124d4b0f158b866a3355f0311e15af8cd2da52093bdae30f44188986a8c4c7dbf6ab010bf18db9a087b29b2aedcbb4f119a4a0c0014130213011303c02cc02bcca9c030c02fcca800ff01000577000500050100000000000b0002010000000014001200000f7469636b65742e7378686d2e636f6d00170000000d001e001c0201040105010601080408050806020304030503060308080807000000100017001502683208687474702f312e3108687474702f312e30002b0005040304030300230000003304ea04e811ec04c00b0ac583142f6c2181f6fa541215ab9b5574c1b8526db5bedb6c3d0dc24c566c85220aae734ac69d173640cac9e34271b371492ec91482096e9d7872625bbb4eebb85ff52f7c23c3c8935a338c47b8529629b03470b1502b12a884e2258ef4c7ee6c840a596d543c44334ac0853a48cc964e128343b3d781280a83a6b789ce8c7150aaa1acb70762f40b4b318ed25ba8e1fbc9efcc9319f776aa3a921c242fe14170ebf890f2980e0851054c53456ef23c81818fbb72388aa8ae3f7bcb8af8a584a7b607e849f1b6aecda340aa6c01df6ac6d7cca8fde336558c535a65412892c0ca60cdfe861d3eba22ae5b16ec8a6469103d59327a807037e37c8277285492c85494fc5900d684766c3ee0ca9adb1257c9562cb97bc7691a2f9ff096b1b4565953c291c56299c3bec621be0fa1874172a8821b2065e6403639afb9149579e2aecf9053f2e5976cf06f5759333094c9e6817c40964f964581529b82ad385431e1708e66a1dcc685cacc821253b251c24e040a5b6dc557b5e4a53398359dcab262d26f5c6090d7d1b23f569d44a19b7c2bb0e457bb2ef77170a7ad007886c2dca3cf4a7897310cc0061ddc4a2ec064b15b684656b2b1272767eee17569744b3e00a8fe0521ffac3fa542190f534f3c3288e8063eb934c88b41a4280674621a775ae5cdc5e28abd698a0db716053105387758deda48d63c14fa2319b5a021b4407c2f54a2801c831a48b7bb4118311b7071220edd08be737b9779f618c844bc6a1075844565a0234dfa1b1b228229e3bca11ee025ccf8614765b3587641c1e6413a279ebac6cf4d07b094fb3aae459b86b37177cb3f4230b1341736f7d111a0331022695af56730e9d0209eb859c98b57198a6ae5e7a1dbf4769dc1997037cc955c13accc48b2029914193a71ab854643cf1cb8a8939b5230ab26a3560f3c293d7b89453509146be245aa23cff7b31bb8a5755893cb5954c070d5b9d2a06f5c4c587809200428358a1a167304c9d3c052acdc0c417b95b45a5887186562f65edf13c0ed4a0be376c375854d7c9c4d08723f0f3272d2c566fa59746db23a15f153f5f2672cd8b324c6005b0c38de260b191485cb363ac4d2bb57b0a45092c2e5933628177a44153e39b563f7b282d4c463932c986e4bc3c72c0c98798c61a5a1d2820530939ccb07b14cc679c417abd7e9a460e76d7ea0c41683358a56ce60705159558a092669d0b67c38b07018d0868b64324b7a1f25580e9a0b0317d7a693e91e09f18d9c1b0d74687330302495894f1930ba26517b46eb6a3b015503d3b80f3694c993b8683aacd810a431c89550b2b68668cff8c99d094c4809b62ac8c93140289ba80a5d703a10d9101219da63f911c85e1099bc27976b12c5022b8e283c7b5cd99ba5a610f6ea740ab21a12b013a5c2c085b5931774c7dc4c22a5420813058d19d11d12c58aa90030268110c4a2c5b5447b0d118de9a52c52a0aa959006ee674fd979ac7511bd1ed50ce8483e35e447fc144b3fcbb77de741f89516b8e496a5d45c9cf11112dc6f73a087bb2811d77719bac816b17259bf993f44cb6f5eac8e8c113af2bc4c85f6326da46ddb13cd2463a11b740367e077a96877d01b9dcdec74ea7b2a7ef197f0e964e62068134dee25e6265b994c5339b6ea7cde8995866a915172308d26dff4f5711668db3967b8debbd79bfc488b99d8fc8cb43b59001d0020866a915172308d26dff4f5711668db3967b8debbd79bfc488b99d8fc8cb43b59000a000a000811ec001d00170018002d000201011603030046100000424104ff635373fbbfbc37444a2026372f57fd06c5205bacfe32b61261a9d29bf1fca57f91ef22cb2ba46af8cf9ae7c3123f56634099af297dcd30835cd81664005fb9140303000101").unwrap();
    let mut timeout = Timeout::new();
    timeout.set_read(99999999999);
    timeout.set_write(99999999999);

    // let record = RecordLayer::from_bytes(fingerprint.client_hello_mut(), false, None).unwrap();


    let mut req = AcReq::new()
        // .with_fingerprint(Fingerprint::random().unwrap())
        .with_alpn(ALPN::Http20)
        .with_timeout(timeout)
        .with_verify(true)
        // .with_proxy(Proxy::try_from("http://127.0.0.1:10280").unwrap())
        ;
    let headers = json::object! {
        "Authorization": "Bearer Upy9fDyueOXiEbON0vRXimg5slXB5wHs+IV75wUbSzZngY0oLn1wJpQw1z3W1yqhu1UUnDUvVg4yrwhyZe9llZUdBEf1DBaF2+N3nSEnwLpmrwQ9iXnSL6LOXKwUhhfc",
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
        "cookie":"JSESSIONID=05304295A550FF08DE1E44A03CDA8CBB; acw_tc=0a065e4717701411754903815e64f1c251caacb791decd35981b455583d1da; acw_sc__v2=69823a8cb1bb76098533c5837be7f69784d38872"
    };
    req.set_headers_json(headers).unwrap();
    let data = json::object! {
      "alpn": "http/1.1",
      "body": "",
      "headers": {
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        // "Content-Type": "application/x-www-form-urlencoded",
        "Pragma": "no-cache",
        // "Referer": "http://xxxxxx",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
      },
      "method": "GET",
      "tls": "Chrome-linux-135",
      "url": "https://m.baidu.com"
    };
    req.set_url("http://127.0.0.1:8080/v1/api/tlsReq").await.unwrap();
    req.set_json(data);
    // req.set_url("https://www.link114.cn/").await.unwrap();
    // req.set_url("https://127.0.0.1:7878").await.unwrap();
    // req.set_url("https://www.jetstar.com").await.unwrap();
    // req.set_url("https://m1.pxb7.com/api/search/h5/product/selectSearchPageList").await.unwrap();

    // req.set_url("https://accounts.pcid.ca/login").await.unwrap();
    // req.set_url("https://xxbg.snssdk.com/fdsf/dsfsdfkdsjfk").await.unwrap();
    // req.set_url("https://www.toutiao.com/article/7600224020776239658/?log_from=99ab1fa2b852c_1769590891442&wid=1769590984039").await.unwrap();
    // req.set_url("https://www.sogou.com").await.unwrap();
    // req.set_url("https://cn.bing.com/search?q=site%EF%BC%9Asite：wLLyn.com&first=0&FORM=PERE2").await.unwrap();
    // req.set_url("https://m.baidu.com").await.unwrap();
    println!("111");
    // req.set_url("https://www.so.com").await.unwrap();
    // req.set_callback(|data| {
    //     println!("{}", data.len());
    //     Ok(())
    // });
    // let context=req.gen_h1().unwrap();
    // println!("{}",String::from_utf8(context).unwrap());
    // println!("{}", String::from_utf8_lossy(&req.gen_h1().unwrap()));
    // req.set_url(url).await.unwrap();
    // req.set_json(data);
    let res = req.post().await.unwrap();
    // let res = req.get().await.unwrap();
    // println!("{}", res.header());
    // println!("{}", res.text().unwrap());
    // req.set_url(res.header().location().unwrap()).await.unwrap();
    // let res = req.get().await.unwrap();
    println!("{}", res.header());
    println!("{}", res.text().unwrap());
    // println!("{}", res.tex/t().unwrap());
    // println!("{}", res.raw_string());
    // let res = req.get().await.unwrap();
    // let body = res.text().unwrap();
    // fs::write("1.html", body).unwrap();
    // println!("{}", body);
}