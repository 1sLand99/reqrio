use reqrio::{json, ReqExt, ScReq, WebSocket, WsFrame, WsOpcode, ALPN};
use reqtls::Fingerprint;
use std::cell::RefCell;
use std::rc::Rc;

fn main() {
    // let mut req = ScReq::new()
    //     .with_alpn(ALPN::Http11)
    //     .with_fingerprint(Fingerprint::random().unwrap())
    //     // .with_proxy(Proxy::HttpPlain(Addr::new_addr("127.0.0.1", 10280)))
    //     .with_url("https://m.so.com").unwrap();
    // let headers = json::object! {
    //     "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    //     "Accept-Encoding": "gzip, deflate, br, zstd",
    //     "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
    //     "Cache-Control": "no-cache",
    //     "Connection": "keep-alive",
    //     "Cookie": "__guid=15015764.1071255116101212729.1764940193317.2156; env_webp=1; _S=pvc5q7leemba50e4kn4qis4b95; QiHooGUID=4C8051464B2D97668E3B21198B9CA207.1766289287750; count=1; so-like-red=2; webp=1; so_huid=114r0SZFiQcJKtA38GZgwZg%2Fdit1cjUGuRcsIL2jTn4%2FE%3D; __huid=114r0SZFiQcJKtA38GZgwZg%2Fdit1cjUGuRcsIL2jTn4%2FE%3D; gtHuid=1",
    //     "Host": "m.so.com",
    //     "Pragma": "no-cache",
    //     "Sec-Fetch-Dest": "document",
    //     "Sec-Fetch-Mode": "navigate",
    //     "Sec-Fetch-Site": "none",
    //     "Sec-Fetch-User": "?1",
    //     "Upgrade-Insecure-Requests": 1,
    //     "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0",
    //     "sec-ch-ua": r#""Microsoft Edge";v="143", "Chromium";v="143", "Not A(Brand";v="24""#,
    //     "sec-ch-ua-mobile": "?0",
    //     "sec-ch-ua-platform": r#""Windows""#
    // };
    // req.set_headers_json(headers).unwrap();
    // let mut len = Rc::new(RefCell::new(0));
    // let ll = len.clone();
    // req.set_callback(move |bs| {
    //     *len.borrow_mut() += bs.len();
    //     // len += bs.len();
    //     println!("{}", bs.len());
    //     Ok(())
    // });
    //
    // // let content = req.gen_h1().unwrap();
    // // println!("{:?}", String::from_utf8(content).unwrap());
    // // req.send_check_json(Method::GET, "code", "0", vec!["msg", "message"]).unwrap();
    // let res = req.get().unwrap();
    // println!("{}", res.header());
    // println!("{:#?}", req.header().cookies());
    // println!("{}", res.to_string().unwrap());
    // println!("{}", ll.borrow());

    let mut ws = WebSocket::sync_build()
        .with_url("wss://poe.game.qq.com/").unwrap()
        .with_uri("wss://poe.game.qq.com/api/trade2/live/poe2/%E7%93%A6%E5%B0%94%E7%9A%84%E5%AE%BF%E5%91%BD/32Y6Wjkc5").unwrap()
        .with_origin("https://poe.game.qq.com").unwrap()
        .with_cookie("pac_uid=0_NattYaCs7NNmH; omgid=0_NattYaCs7NNmH; _qimei_uuid42=19c1f11150d1000f92fe16d850a9c40cf94ef1d39f; _qimei_fingerprint=f3dc39297e432b1f08da57e9904a8f52; _qimei_q36=; _qimei_h38=a549811f92fe16d850a9c40c02000006b19c1f; _qpsvr_localtk=0.2296543129537577; RK=WPZCq/wl3I; ptcz=c338dead622f05f0d8467ac10589e7e45326b81d67ff476b9643f933cfdc644a; eas_sid=M1b7q677w9D5R5P2L8x5g4p313; eas_entry=https%3A%2F%2Fgraph.qq.com%2F; POESESSID=939e23af876572a0b2852b2e183e20cc").unwrap()
        .with_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0").unwrap()
        .build().unwrap();
    loop {
        let res = ws.read_frame().unwrap();
        match res.frame_type().op_code() {
            WsOpcode::CONTINUATION => {}
            WsOpcode::TEXT => println!("{}", res.payload().as_bytes().len()),
            WsOpcode::BINARY => {}
            WsOpcode::CLOSE => {}
            WsOpcode::PING => {
                println!("PING");
                let pong = WsFrame::new_pong(true, res.payload().as_bytes());
                ws.write_frame(pong).unwrap();
            }
            WsOpcode::PONG => {}
        }
    }
}