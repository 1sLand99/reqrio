use reqrio::{json, AcReq, Fingerprint, Proxy, ReqExt, ReqGenExt, Timeout, ALPN};

#[tokio::main]
async fn main() {
    let fingerprint = Fingerprint::from_hex_all("160301020c010002080303247340d23c347b7a66d5a7eb4eccb285012ce86f658d0b45e1588354c51ca4792009a85c66f5ba581afec042a139153e1d4016b38319618311c2e36ae2a76c924000200a0a130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f00350100019f8a8a00000000000e000c0000093338686d7a672e636e000d00120010040308040401050308050501080606010033002b00291a1a000100001d0020b511c3d06f2e67ec1dbb9bfc333511feb597f20e5c0d3a0aa3ab1044cb63001f00170000001b000302000200120000000b00020100ff01000100000a000a00081a1a001d00170018002d00020101002b000706caca03040303fe0d00da0000010001f80020c8665dd625d0a4c92ddc132c7d1ebca65a14a278f07375a85d545f630e18872500b02461426ced15d88bd0d907fffb17ab849140d48cad81bbfe8e7b7e1846ccf1d6be156a397fbeede0092f5eb5f6c35e9c1e8cf8738d8cb53c21f25bcb7934a2709ad124490010ada60f44741c97fb56976201c8ff3194204e37c82d3bbbbe395bed90a2a9e9d692d662594d9e8676bdea51a07ce7cdcd882929ed7bee454e2c3a39a80b90ceef6a1272e87627a7f40f96314d67f7857a1bfccc776a61f55f8922047c97b55c001193aade01aa6573c0b5446900050003026832002300000005000501000000000010000e000c02683208687474702f312e319a9a0001001603030046100000424104ff635373fbbfbc37444a2026372f57fd06c5205bacfe32b61261a9d29bf1fca57f91ef22cb2ba46af8cf9ae7c3123f56634099af297dcd30835cd81664005fb9140303000101").unwrap();
    let mut timeout = Timeout::new();
    timeout.set_read(99999999999);
    timeout.set_write(99999999999);

    let mut req = AcReq::new()
        .with_fingerprint(fingerprint)
        .with_alpn(ALPN::Http11)
        .with_timeout(timeout)
        .with_proxy(Proxy::try_from("http://127.0.0.1:10280").unwrap())
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
        "Connection": "keep-alive"
        // "cookie":"_spvid_id.ab05=211d3f05-8cb7-40e6-aa8e-595b45cf7e0e.1770095266.1.1770095266..22c133ab-52af-492f-8532-a1b936acfbcc..a8f75e61-9d1d-4143-ac41-3ba5e9131b2d.1770095265854.1; _spvid_ses.ab05=*; _spvid_=e68ffafe-bd86-43c1-80ec-560de9f1bddf; ak_bmsc=B54C35CE57EA175DB8FFA5038485F93D~000000000000000000000000000000~YAAQBNYsF4CkSBGcAQAAok3mIR4dx1WmSty0j4DtoVhdY3UPJ22h4jdleBRwYQGNUZEpcRjx7iP+5EQq+ZsKFsDhvXqJ/dmk2rylQY+3EW75sRsa+BdFHMx7dUoRAEwqTNBE8GdgFKMlyAiLU3V40TWM/6lpTVgwEMR4rbqdgQLs06jrHCinI9oHmwSCacDA7lzf+5IiwOKYmzqNazYn/WyC4AMKCnOqnKEzccbAfm0tYo+aujjUbmo9VzwBBWeik6VC9jpdEMpMw2ffv6UmDpCpjvGId0+1vw53v7tHDiDWVs6z+oOkfzuIrJt58U76FT4oUTpRAEifsArt1Rt3ia7IwD7HmOPdt+pGwEAdrKPXpNRAcaxS5VGSG1P5K+qb; ADRUM=s~1770095269046&r~aHR0cHMlM0ElMkYlMkZhY2NvdW50cy5wY2lkLmNhJTJGbG9naW4="
    };
    req.set_headers_json(headers).unwrap();
    req.set_url("https://accounts.pcid.ca/login").await.unwrap();
    // req.set_url("https://xxbg.snssdk.com/fdsf/dsfsdfkdsjfk").await.unwrap();
    // req.set_url("https://www.toutiao.com/article/7600224020776239658/?log_from=99ab1fa2b852c_1769590891442&wid=1769590984039").await.unwrap();
    // req.set_url("https://www.sogou.com").await.unwrap();
    // req.set_url("https://cn.bing.com/search?q=site%EF%BC%9Aqq.com&first=150&FORM=PERE2").await.unwrap();
    // println!("111");
    // req.set_url("https://www.so.com").await.unwrap();
    // req.set_callback(|data| {
    //     println!("{}", data.len());
    //     Ok(())
    // });
    // let context=req.gen_h1().unwrap();
    // println!("{}",String::from_utf8(context).unwrap());
    println!("{}", String::from_utf8_lossy(&req.gen_h1().unwrap()));
    let res = req.get().await.unwrap();
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