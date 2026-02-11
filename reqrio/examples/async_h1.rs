use reqrio::*;

#[tokio::main]
async fn main() {
    let fingerprint = Fingerprint::from_hex_all("16030105db010005d70303df140127aab85bbeb20fe797c97a5ce9b5a241fa4a37149a27bc589bc8e8d820202cccab4c63c2e029f00a0e369f9acae0996c40399d3d48097f57072317a2aa340014130213011303c02cc02bcca9c030c02fcca800ff0100057a003304ea04e811ec04c01b1c3e8b09a266b4c21c032b041846e4599993b0c0630340e8207066f6a1de84c5a933965b1281bb402cd5375b0278b802e344f9a5bd605a5a6eb151525b19ed5c30e16bb018f56c46c7198786a84b43632b1b7ad5699cd5d3b935ea04c846208d3b54347578bf43b8a24c0ad0620544289de44b4ae549098ef9a8e2f1138ffb2916398ed9e0a649993d8b80842774083d249ffff6b111a74fb3243941d7b341f68525401f90f42b55627e3ca376d2ac00ad77b640b509bbc81b78facf81e60effe9830bca5a3897ba81593bc4b27f3eec111ed322c4417782b56107aa26dca148c7f6aa7f065efdf367deba4562721b07011527539c68b916c302bbcbc40fe0513d5c1a5aa223cc610bae9fc12f8a25abfe61c472961662ac84606405b5a78fa4c08b1ddc2ef09a63d75bb3003a054c637b04e623d3e0a28e9403c24a09ca1076071930e8f4880b0c423c2425b09445589102e578159d129c7fcc085bf976ec9836b8c2395a090e91596ff5658b46a04544f84bbcca35f81b8dfefaab6be80d1feb8194a51c2b645e47e1a868a78006b06f77c359edd34b74714892d0155fb63a600c3d10f91c3dd9c96aa94c00493c12d56473ca2efdc3b763c48bc05c653fc2c35508bd230070b18287f4675d4606273470845c945b4d8c4870ab8dea6b12ba6b6cdc5501315c94e3501257d618ae8abc3d20ada3fb54abf6968c88871d97b0f69b00b442545988b4c038012a18c83dc6cda526806bb128dfe0b064d71568409287619947ba2f64818af0e67f845bc4bbf704f0e77807a90c45c01737743e714791caac03e2336976b41b46c73d2cb3832d83c5565551592a45e0340815655bb67bc9874b5fc9a82b2db51a1b3ba2c16723daebb0890ba6d27c7316b7bf032bc88b7675f4b53f5d0860eca303d6f881b35c5ff3c5a262210b36d77039487845299c65381efa063eb1bb9b08742e40f36228641261007639914ad18c011d668855211985233035463fbdf92f1672be2550973ec85aea7717e59bb8c99231269948cc8a3d08792f5b4b4db37048f18b240d82a17c321250a032707baaa5a5badccc7429c9af6ab29c781c9473e2b3fe45214dba950fba501f2a31f4cacde18b42da465f4143babe979cda48af48b8c042448874f843d3b15c6bd8c538b73040d8cf8be675c4e1b5eab825fbecb3fb069f78cbbd775b1d0ffc18bcc13540f67c29b1159e634ceb939e8c2bb8ef579b55637c197b688df802bc812e3ad5b9c86b7336532d639548b4d24e90fc2106c40dcd69b6d4649356d39a0e0007fbd57d09c59bd1c9a3bd54564dda998b0279e25293b6493c4a853b248541977bb8dac602abd29c1b6487c7b420a2ab7357627bacfb0e02094bab084071fcca6c4a0600e9cce72a81d61ba556fb353297ccd478a6eff1cf4595c06dc176732538a8b9cb5b956b35d87dafb32ae422011217246b165a0f86cf363c955bcb952e47753f4a744c19a28a93b59cc945c40026a1b57194db12d702367e121e15a993e3c330e395c9fb71c3717c607d978a69b156094881f9e041ee7cccc308cb200b8f6b0a5ef6cc05edf3c828637858c5714c014dad185afc73bb379a42d15c40a601b5a7755059249953c5b98b2f4f52cabf6e2e3ba02af2858bd550c1a08b47f8f409c1fa539e0861d6fd58a4224fa10c08ac02c7ca13d44fce1176a39df2a06ceccf2b693d001d00209e0861d6fd58a4224fa10c08ac02c7ca13d44fce1176a39df2a06ceccf2b693d002d0002010100170000000a000a000811ec001d0017001800230000002b00050403040303000b00020100000d001e001c0201040105010601080408050806020304030503060308080807000000100017001502683208687474702f312e3108687474702f312e300000001700150000126f70656e2e77656978696e2e71712e636f6d0005000501000000001603030046100000424104ff635373fbbfbc37444a2026372f57fd06c5205bacfe32b61261a9d29bf1fca57f91ef22cb2ba46af8cf9ae7c3123f56634099af297dcd30835cd81664005fb9140303000101").unwrap();
    let mut timeout = Timeout::new();
    timeout.set_read(99999999999);
    timeout.set_write(99999999999);

    let mut req = AcReq::new()
        .with_fingerprint(fingerprint)
        .with_alpn(ALPN::Http20)
        .with_timeout(timeout)
        .with_verify(true)
        // .with_proxy(Proxy::try_from("http://127.0.0.1:10280").unwrap())
        ;
    let headers = json::object! {
        "Authorization": "Bearer Upy9fDyueOXiEbON0vRXimg4tlrO5wTs+IV75wUbSzZngY0oLn1wJpQw1jnV0Cqku1UUnDUvVg4y/wwkNOljlJJKVRbzDETSjOd0zHotk+s3+wM63SDWeKXOXKwUhhfc",
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
    // req.set_url("https://127.0.0.1:3453/v1/api/tlsReq").await.unwrap();
    // req.set_json(data);
    // req.set_url("https://www.link114.cn/").await.unwrap();
    // req.set_url("https://127.0.0.1:7878").await.unwrap();
    // req.set_url("https://www.jetstar.com").await.unwrap();
    // req.set_url("https://m1.pxb7.com/api/search/h5/product/selectSearchPageList").await.unwrap();
    //
    // req.set_url("https://accounts.pcid.ca/login").await.unwrap();
    // req.set_url("https://xxbg.snssdk.com/fdsf/dsfsdfkdsjfk").await.unwrap();
    // req.set_url("https://www.toutiao.com/article/7600224020776239658/?log_from=99ab1fa2b852c_1769590891442&wid=1769590984039").await.unwrap();
    // req.set_url("https://www.sogou.com").await.unwrap();
    // req.set_url("https://cn.bing.com/search?q=site%EF%BC%9Asite：wLLyn.com&first=0&FORM=PERE2").await.unwrap();
    // req.set_url("https://m.baidu.com").await.unwrap();
    println!("111");
    req.set_url("https://www.so.com").await.unwrap();
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