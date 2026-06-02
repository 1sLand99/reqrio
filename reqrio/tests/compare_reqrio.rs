use reqrio::*;
use std::time::Instant;

#[test]
fn compare_reqrio_multiple_requests() {
    let url = "https://cn.bing.com";
    let request_count = 5;

    let mut total_elapsed = 0;
    let mut body_length = 0;

    println!("reqrio: url={} count={}", url, request_count);
    let mut req = ScReq::new();
    for run in 1..=request_count {
        let start = Instant::now();
        let res = req.get(url, None).expect("reqrio get");
        let elapsed = start.elapsed();

        let status = res.header().status().code();
        let bytes = res.bytes().expect("read body");
        body_length = bytes.len();

        total_elapsed += elapsed.as_millis();
        println!("  run {:02}: status={} length={} elapsed={:.3?}", run, status, body_length, elapsed);
        assert_eq!(status, 200);
        assert!(body_length > 0);
    }

    let average_elapsed = total_elapsed as f64 / request_count as f64;
    println!("average elapsed: {:.3} ms", average_elapsed);
    println!("body length: {}", body_length);
}
