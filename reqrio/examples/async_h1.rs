use reqrio::{json, AcReq, Proxy, ReqExt, ALPN};
use reqtls::Fingerprint;

#[tokio::main]
async fn main() {
    let fingerprint = Fingerprint::from_hex_all("160301020c010002080303247340d23c347b7a66d5a7eb4eccb285012ce86f658d0b45e1588354c51ca4792009a85c66f5ba581afec042a139153e1d4016b38319618311c2e36ae2a76c924000200a0a130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f00350100019f8a8a00000000000e000c0000093338686d7a672e636e000d00120010040308040401050308050501080606010033002b00291a1a000100001d0020b511c3d06f2e67ec1dbb9bfc333511feb597f20e5c0d3a0aa3ab1044cb63001f00170000001b000302000200120000000b00020100ff01000100000a000a00081a1a001d00170018002d00020101002b000706caca03040303fe0d00da0000010001f80020c8665dd625d0a4c92ddc132c7d1ebca65a14a278f07375a85d545f630e18872500b02461426ced15d88bd0d907fffb17ab849140d48cad81bbfe8e7b7e1846ccf1d6be156a397fbeede0092f5eb5f6c35e9c1e8cf8738d8cb53c21f25bcb7934a2709ad124490010ada60f44741c97fb56976201c8ff3194204e37c82d3bbbbe395bed90a2a9e9d692d662594d9e8676bdea51a07ce7cdcd882929ed7bee454e2c3a39a80b90ceef6a1272e87627a7f40f96314d67f7857a1bfccc776a61f55f8922047c97b55c001193aade01aa6573c0b5446900050003026832002300000005000501000000000010000e000c02683208687474702f312e319a9a0001001603030046100000424104ff635373fbbfbc37444a2026372f57fd06c5205bacfe32b61261a9d29bf1fca57f91ef22cb2ba46af8cf9ae7c3123f56634099af297dcd30835cd81664005fb9140303000101").unwrap();
    let mut req = AcReq::new()
        .with_fingerprint(fingerprint)
        .with_alpn(ALPN::Http20)
        .with_proxy(Proxy::new_socks5("127.0.0.1", 10808));
    let headers = json::object! {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        "uid": "1985208667858714624",
        "Content-Type": "application/json",
        "token":"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ3ZWNoYXRfcHVibGljMSIsInVzZXJJZCI6IjE4Nzc1ODcyNjU3MDczMTUyMDAiLCJuYW1lIjoi5b6u5L-h5YWs5LyX5Y-35pWj5a6iIiwib3JnSWQiOiIxODc3MzM4MjQ2MDkyODE2Mzg0IiwiZGV2aWNlQ29kZSI6IiIsInNhbGVTdGF0aW9uSWQiOiIxODc3MzM4MjQ3NzcwNTM3OTg0IiwiY3VzdG9tZXJJZCI6IjE4Nzc1ODcyNjU4NTgzMTAxNDQiLCJzb2NpYWxDdXN0b21lcklkIjoxOTg1MjA4NjY3ODU4NzE0NjI0LCJleHAiOjE3Njg0NDA3NzN9.lFiEpgMQfCBEGssuCRAHrVD-YamH5vYose4hUEnZg72V8XhSIEHXfLL1_eZ96fkjZD_wE-JNrkeHTMJ_WAjMLZ5DRnGiKN5n0BOUyQayvUZ_SxoVryLPoJ4W19YhYAYN5yZXLpGakymtqr5q3peOR-Sy8-tLLJNolnuTNfRRMaQ",
        "Accept": "*/*",
        "Origin": "https://ticket.sxhm.com",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "sec-ch-ua": "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Microsoft Edge\";v=\"120\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\"",
        "Referer": "https://ticket.sxhm.com/quickticket/index.html",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Cookie":"yrLQQyDMDE1ZO=608wtJPUPLKBJVe6Tz1eB9cSEtX55rEaNgz_xzFFR4vTmeBL1wE8H6VNN0qyN2nkDewI0yK3y0.GXVHAAXyrFvaA; yrLQQyDMDE1ZP=0Yn0ZcLnGoSPFQhck3P57_Q4U0jIs_8V2TH1280.uDyhj1YzCNm9uFfROinxkdxymwO7MqkMSTVzt6Y3GCKFWfSuEUIjAl8bTezWlSR8IyZDFtX5PkpDMg3nT74FwXuGmt2l76bK515gCLTH1TtfQcoPVz1DLSW5feuDCN7sdcuKxwaQ7oLf2TZ7O2K1C3u9DghWIHCjgI6jFVEzeJKnhXlgjJAd5BSb5eBOuYiwXI49KAvAe3XtxYCFbZW.URJ8MfFaU7x_JMislcGeLF_Kzn119ro9Wgqup0y_ITliU.R7Z8D02q7ytWe9pjg7AxnvF33R9prSimv3kgof2QPKoWITc0Z75yJuH8iAp9PdeiJkMb6okRb2GouUT3tCUvJ3TRZUARz_HOX8K4ln_snmrVq"
    };
    req.set_url("https://m.so.com").await.unwrap();
    req.set_headers_json(headers).unwrap();
    req.set_callback(|data| {
        println!("{}", data.len());
        Ok(())
    });
    let res = req.get().await.unwrap();

    println!("{}", res.raw_string().len());
}