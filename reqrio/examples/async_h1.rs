use reqrio::*;

#[tokio::main]
async fn main() {
    let mut timeout = Timeout::new();
    timeout.set_read(99999999999);
    timeout.set_write(99999999999);

    let mut req = AcReq::new()
        .with_fingerprint(Fingerprint::random("122-722n2ck-6p7d3u6k722n2ck-6w21166k").unwrap())
        .with_alpn(ALPN::Http11)
        .with_timeout(timeout)
        .with_verify(false)
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
    // req.set_url("https://shopee.tw/").await.unwrap();
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

    req.set_url("https://m.so.com").await.unwrap();
    // req.set_url("https://doc.rust-lang.org/").await.unwrap();
    println!("111");
    req.set_callback(|data| {
        println!("{}", data.len());
        Ok(())
    });
    let res = req.get().await.unwrap();
    println!("{}", res.header());
    println!("{}",res.raw_body().len());
    // println!("{}", res.text().unwrap());
}