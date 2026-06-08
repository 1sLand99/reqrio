// #[test]
#[cfg(reqwest)]
fn compare_reqwest_multiple_requests() {
    let url = "https://cn.bing.com";
    let request_count = 5;

    let client = reqwest::blocking::Client::builder()
        .user_agent("reqwest/0.11")
        .build()
        .expect("build client");

    println!("reqwest: url={} count={}", url, request_count);
    let mut total_elapsed = 0;
    let mut body_length = 0;

    for run in 1..=request_count {
        let start = Instant::now();
        let resp = client
            .get(url)
            .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
            .send()
            .expect("send request");
        let elapsed = start.elapsed();
        let status = resp.status();
        let bytes = resp.bytes().expect("read body");

        total_elapsed += elapsed.as_millis();
        body_length = bytes.len();

        println!("  run {:02}: status={} length={} elapsed={:.3?}", run, status, body_length, elapsed);
        assert!(status.is_success());
        assert!(body_length > 0);
    }

    let average_elapsed = total_elapsed as f64 / request_count as f64;
    println!("average elapsed: {:.3} ms", average_elapsed);
    println!("body length: {}", body_length);
}
