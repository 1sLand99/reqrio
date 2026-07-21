use std::fs;
use reqrio::*;

#[cfg(feature = "log")]
const LOGER: Logger = Logger {
    module: &[],
    debug_file: None,
    info_file: None,
    warn_file: None,
    error_file: None,
    out_file: None,
};

#[cfg(feature = "log")]
fn test_log() {
    set_logger(&LOGER).unwrap();
    set_max_level(LevelFilter::Debug);
}

#[tokio::main]
async fn main() {
    #[cfg(feature = "log")]
    test_log();
    println!("{}"," 3fddsf".trim());

    let client_hello = hex::decode("16030108080100080403035cc0ca906bb559aac3b8973ead29a0ba8fe44c6d49c4e014f0eb8cef0143e96020bd4398de18812cc4474b9d4d983b9e2c54aad8f8636bbc2c000b4ec3782166230020dada130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f00350100079bcaca0000003304ef04ed1a1a00010011ec04c0e2ca7e6acb4a7bd48cc6267659cc683854471b181fd6e07de6b231427b129759bc60325d4d02453e11425b720e1da783282b7f0b927bf3677c3cf80aac149df44a65dbc7b3013a1176c6cfa2170613730a8d4335ec6c8398ab2fde274b3c4a1b02d34fd4d1cd4f672411580c1f776b2947682b137f56197fc57319ab47521f624107191ce85a46a9e43abb572b089918a63178abdacd37796f80d4586a419187f8983f8c0486024912d9c8822660b8957ad5c57a034932bce9c325523bb4d06556f5b5c36a50bbec0538436a20f05d74bcbbe1431767b08eb81b125a252acc1605408b238d22498330a3d5f8bd625704d12289502a0fae1b48dcfb53fb17669632aa2ef876b826861f2164be5141d17aa140523d7676acbae670ae3767dc8009d9e61d510a311d185716c066714c9bc99851e3d22a7f9132ae3845e52a0048f3cc994376d4e1844a961ec3781edd1979a8741fe2f51bc01b542ce2596dea80ea910282f27bf847b64b69c5f8d83142d37c9dc1c27944b6637a9c855b587422bcb458460666b8a9356c13c37918f76866f289fbb74337d866e8f2c9bf23826707981546a9a2154030d06989799390c490c80228bb9389e541c0d91bc69bdb730019a02e5357ab5bb395231a59b90002903a8dc241aa170b76cba25a6c2b24f804b0c729747960d2e23f6c2987ade48680d0c1151a843f103b3df21767dc3f52fa16080b28ebb8b8ba944e884729478c3532d73a9568589904069095aa55897b5bfa72188170115525f19b5103528b48d78a27da34e881b10d0b43f043b50c6b8848e2b5f3564a9ad03ea3165cd5805a086c3323b73aec9522f30cb15c78cff24c6051e31e1658ce31d574d694260dd664b86845adc0cdd7c27525f6c8d3f8806205caa6324d8f9ba2cde866350586932c128b0240f82329413a369d07b6f1f2bc82a892e224088f8b79c7671beca6cc45d30f79298ee1b34a59ca9740636876b9a24c1c844d088a1256a4ed0937a82ac456cc8e37007c5cd163f3b48c6d938ad1250774e51303e88790b5191f695df171b1107b7ddac45385a54bc913553ec1caa8375869930e103b5f054487e49721ea8827bc74117b6c5e263170e359162e8442812cc5af308293187999f53ff9362f28825f451cc58fba6430f10380742f5bf2622e4753ea10445fd93c197283756a9f17e3b45d865722f2b4f81badfbc407f15a87cb426dfc713063511539784006429cb1c59df35619f6bc864516333bf4257bdca6c9aa4865b5b2e4d05a1773ae78f995298a28f78158dd45b1bee69b49c38955f7a135e1695a8371ed603ce8b566d426a86c526c8f226fd66c6dd0639006d71d74e8224cc9ac2aa99c3ba26f8bc5674c420850574044f52118f8caaac033ae5a4857555ff8876df488be04982b35574f633ac77da8b2eccb07a8544ed714bcf0e87828463a6ca864da07427577945df1877c760123462c07802880e71dfb730777e11a3500642f5a4bac503e5fdbcb74bc5e281b8ec7608dc02037bdca2fe98534c886beabb3078c52a706939938670baf6103a4b2a71d37c538cb308c7040e11b8362f5c16fd2c3470405e3b1b54e17509f7aa4e9eca7ab2533f0753f13d1c3e70db469cec138195c26dfa6e913c1502ff673ad89da782d5730e7839118f185d4853613fb27fafbd6fcdeabac8cbd2cb54ff7cab98b8e18bade73322c001d00208dbd5ea8a10fcf78c32564f41837a5227c5f9e33cab7e8420ad9675e73b99d7ffe0d00fa0000010001bb002012000839e58c06e36d44cb0f67bbf609915d8584b23b7c196c4c5112a6fbb80200d0580b447bf18bb437b89de89306b701f5def505e76dd50fcba098f1281014e2cbd0fe83207c30326cf527df277c7204edff3119ed4a5162336ca0e422390601dbe608cab030267a0031eaaed54c5948d1a5a4ae89885e04f10d436821c9d8ad925f785587b7efe0bc46b6191ba4b043eb45c441ba3b08bef2ebdeb84e03d25068234d403f340fd1df03115ffd2d60ef46f97fbebe634bad9b0dcfc839b501f30f0c3335691b9a9340017994f3beb571322319fcbc82df8c75e1b4f296f90dbb97dfbecde6326748f7a2264ca0922c1bb00012000000000010000e00000b636e2e62696e672e636f6d002b0007068a8a0304030344cd000500030268320023011400000000215c0fdeab332447b6ded6ec22c2b5e159c9e120eab2e827b4f3774e0e81ec972b74abc57914c670caff95f2b1499553eda241a4402063954e5456d6636c68be77d16c2ef3eb90ca6f0b6c06531bbd8ac4097f8be3048c04d8c4538e62455f9a1d5bc0bf0c74714355d98ab2ae4d46a0f8f53255fc81ee25dc70ad4528d275ac9b9f2d586c99d8618c1effd06dff7b97d0d01000f7228796bcbe3e9b0f05f9a49f0db4e80fdb122e998cf9df3574692449c00acb19e89775f93e84fd3da79fe55d8cdbbe76ed950ef55fa6b3fe4b1fd23df5e00d539a739169d8147a4d65e3e7ff8a0550ff84423255fc997028140c9add4a31b25f6496f7f8a5154650a38164d5b25049c1427fe85cf9efe847da2a27000b000201000010000e000c02683208687474702f312e31000a000c000a1a1a11ec001d00170018001b0003020002000d0012001004030804040105030805050108060601002d0002010100050005010000000000170000ff010001000a0a000100").unwrap();
    let fingerprint = Fingerprint::from_client_hello(client_hello, fs::read_to_string("TOKEN").unwrap()).unwrap();
    let mut req = AcReq::new().with_key_log("2.log").with_alpn(ALPN::Http20).with_fingerprint(fingerprint);
    let url = "https://www.maybank2u.com.my/home/m2u/common/login.do";
    let headers = json::object! {
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "accept-language": "zh-CN,zh;q=0.9",
        "cache-control": "no-cache",
        "pragma": "no-cache",
        "priority": "u=0, i",
        "sec-ch-ua": r#""Not;A=Brand";v="8", "Chromium";v="150", "Google Chrome";v="150""#,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": r#""Windows""#,
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "none",
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36 Edg/148.0.0.0"
    };
    req.set_headers_json(headers).unwrap();
    // let body = "lll-ecom-correlation-id=A4ED3840-8BBB-1F4B-C654-3A13E96A4AA0; lll_client_id=87b757c01925267e46ba090f5beaac0c; akacd_shop_alpine=3961650874~rv=29~id=ea417bb57c86ffc3bc03a9b435003763; lll_edge_geo_data=city=HONGKONG&state=&zip=&country=HK&lat=22.30&long=114.20; bm_ss=ab8e18ef4e; PIM-SESSION-ID=rNLtdAlQwEi7ZWRh; bm_sz=00171E18FEB2330A2A074114C45BD853~YAAQbmATAvbKHUifAQAAah1+agB6gnOQ0NinvXS4OZa7cI9zoG/A7ZOuBAKTFONlm+ycvF2o4uXTre7XDm2QVrMKic8dT/1U5siy8fntV754+urHR2bKut1SMPDG/loLwIrhW3K7nPMf1CFoo0VQDhhNl/mlmatztsMjrYdMMwdAik0iGnV2LmapRc4+XKjnNcs8j8IwxGi8GI9/X1ok6b/oots6AvOALgV2VuB0TUAb+8agetcExJfMrH1Acb41e+Ij7RpGm+Xj90KmWERpEs2mvN3YcrIbHIU+Pv3JFmInNtB7pB7zXplLlMcPnSDGWoUUmZrsb+HWDQ8EYoQDj4BjfXbPVlmKS3NPEGqM23D6gYE9O0MPAM0lVHWwNxjrTnXtjVUlgdiCXKh5AUAvlQAQd7JlK550jLNBDoS4p9F8Gr7c6zY=~3224114~3162678; ak_bmsc=7128134C99E83EB2CEB589C1AD5E1CE4~000000000000000000000000000000~YAAQbmATAvvKHUifAQAA0h1+agAnwgVNWCoQyiMuYYwg6hymjd6H6I9sPbYPdlsBbQ3YSQsEeoK0y0HecUwToxG9m6ox8yARaWfxvLywr7GD1IkkdNw/yGdrT2AOgvPGVE/DZq7jmlCh4G1nJXxbqF+ew6pmsFavRK7obMt3rDQ7WhX8F0YjIKm1X+eFo3xH1DFpkxPlkhWHWHCNSMB9Kbbiqc0e0OrWkG0z1O0E0jLOAPYjJbwdm+uzAuxXpb1UGH6KWWShuVnzNIC3Lt5GdczlWsIO9TEs/RsDlmOSwk75+mt6JsKHlSfXF2WjzFKjeOzWQWcPWw8WbwgB+BcZYJnlhNwn/m+viAvexQI/0jkq/wIqufZ2u/7X07ElYj4jaLwQcZJ+Tj8FphF6h0b+4YcLH3nNbtbRd9dBLnLQ57vTxKpkhrlTL/mW; kameleoonVisitorCode=87b757c01925267e46ba090f5beaac0c; _rdt_uuid=1784198082030.f515d3f5-5948-4406-a3a4-cf6eb92f854b; QuantumMetricUserID=01b030b33cbc03aa6e33f23c2666eeda; _ga=GA1.1.14457051.1784198082; bttnsessionid=sess-H2qHL643wyET2kIctJBtqe84GNsFfejXQZ5DqJ51aWxT9; lantern=d94d0422-a1a0-48bc-a96d-ff7d54928dfc; _evga_8f06={%22uuid%22:%2275e8d0325eb73f72%22}; _sfid_cc29={%22anonymousId%22:%2275e8d0325eb73f72%22%2C%22consents%22:[{%22consent%22:{%22provider%22:%22Consent%20Provider%22%2C%22purpose%22:%22Personalization%22%2C%22status%22:%22Opt%20In%22}%2C%22lastUpdateTime%22:%222026-07-16T10:34:44.350Z%22%2C%22lastSentTime%22:%222026-07-16T10:34:44.360Z%22}]}; kampyle_userid=e0d6-4225-2fa5-5bcb-1a50-c25b-17f0-3cab; kampyleUserSession=1784198085095; kampyleUserSessionsCount=1; kampyleUserPercentile=16.56038758534091; kampyleSessionPageCounter=2; akaalb_Shop_ALB_instance1=~op=shop_mwa_shared:mwa-shared-euw2|upper_funnel_static_alpine:upper-funnel-alpine-apse1|~rv=20~m=mwa-shared-euw2:0|upper-funnel-alpine-apse1:0|~os=3ad3acca926c302b084e12bf3b209756~id=2069cc8b73e76fe04112da4fb6543a0f; UsrLocale=en_US; sl=US; ek8_guest=true; ngcKongProxy=true; diasKongProxy=true; gtKongProxy=true; cosKongProxy=true; smsKongProxy=true; diasLoyaltyKongProxy=true; pers_seg=eyJnZW5kZXJBZmZpbml0eSI6ImFsbCJ9; authToken=eyJhbGciOiJSUzI1NiIsImtpZCI6IjYzNDYwYzA1LWRlNzAtNDFlZC04MmRkLTI2NTMwNmFmMjk2MCIsInR5cCI6IkpXVCJ9.eyJVVUlEIjoiNjBlNjUxNmYtYTUyYS00YWQ0LTliYjUtN2E4OGRhY2UxZWEyIiwiYXVkIjpbImh0dHBzOi8vY2xvdWQua29uZ2hxLmNvbS91cy9nYXRld2F5LW1hbmFnZXIvMGY1NzhlMTQtNTVlNC00NWI4LTlhNjUtOGI3MjYxNTU2ZTgzL292ZXJ2aWV3Il0sImNsaWVudF9pZCI6ImJmODFiYmU3ZGIwYzRhZjZiZGU1YzExOGU1NGZlMWI4IiwiZXhwIjoxNzg0MjA1MzExLCJpYXQiOjE3ODQxOTgxMTEsImlzcyI6Imh0dHBzOi8vZzR2MXNpZ2YwNnJ0cGV0Ni51cy5pZGVudGl0eS5rb25naHEuY29tL2F1dGgiLCJqdGkiOiIwMTlmNmE3ZS1hMTAzLTc4ZTItYjkxMi0xOGJjNTMxYzJmMjUiLCJuYmYiOjE3ODQxOTgxMTEsInJvbGUiOiJndWVzdCIsInNjb3BlIjoibmdjLXByb2QtbmEtd2ViLWFwcC1jdXN0b21DbGFpbXMtcm9sZS1zY29wZSIsInN1YiI6ImJmODFiYmU3ZGIwYzRhZjZiZGU1YzExOGU1NGZlMWI4In0.tZHCn5UJhtWNy-xVQkEHj9ly5c1nPAIM5OwzofOxXJMOXkLB2PeswG4VVgD4wORwMOo2QH_QfzhR_Xi8jiubVvMkSfR_eBexh3diomPEU7iikev5UrGL5HFnw9oihe98nZqIWyiJ4Wdd__G575QGvYCc8tCX3W6T_UDFw4wKuxTrClpUOipBqX9XFIKsWNQF4iYbVI6DiGTDrhMNNFPt9qZrAaBLWCH-dLunQpKrsJlPAlPSV_PZrhB4FG-JCEPStAHYrBBCY_2LDKh9dM2ZJwro7fiIVim6a595OZuky1VFzLU3Jfkk2hAzhHJsUBdtWPS6LpEPcF6RPH4C7zd2-w; ajs_anonymous_id=206b1fe0-a069-4a48-8d41-dfe90f79f1f3; _ttp=KUJfMpWpfxIWI2rvudz0UJ5bkZ9; _scid=WwPC1F2aez5Pu78zCMfjiUGBAZ9qfx7S; _fbp=fb.1.1784198143830.462252227; bm_so=91BE290C9E5DBF296D9EB9D884C8A0D4087DA08E8879E69B12514398D6BA3C1A~YAAQq9TOFwZZw2CfAQAAvNiWagiwl4Wka326s6NqWtc9R02TUO/lVdGQGfOz+8p/2XN85djD4Y9WmEOmdRxFwsWot8ifXQTlC0EFa2tcEJgqVzduHhT6CMUUB1VzYw7YeSbS0SxLTc8QrR8XK3Ieag5wJzEQW4gg8m94x8aB65rd2/0kMgAY6o/UdO0XNvjsLqetWpzI3QTCNZQ26skoSm/F7UCbk/MIYh/FFV4odlQN5CWj57xg2mIVEWw4iFyFuMOtyjFtVOiEeH2e/P22TZhnlxNUOITmnUUL5UIhLqFdRTU7Ps8AflhEvtz+WC6RoMzvi3yWUtziXKJca/syFh/zZGA5ZcwK7MzL+iw3Rv26Hj/WvU8Te+8E3eM/FR+lWkXyoZqTvMk6eAES9pOQbfZvZxsoQWbtGenHdBdQsk9L/bvpaagLNJj5DvndYv6TKCJzsRCp/9oljo0MvHRA9qXos4/S; bm_sv=9EEC2C61D05262A70F4383DE2F0A86FE~YAAQq9TOFwdZw2CfAQAAvNiWagATGQ2bK7i/rjyS0AaLMGqgYzFgllQUP7o4VXKuS3/hGxRPiLLFwssg6U3aOCp2VRkh3pZVX6YdacGhtx02u5E0KS4lGTbgLD2Mj5tbVsqc42jStsd0Ew5mGuFmK/GovprI6nr5RO2YrVsq2odFU6Y9XYwytK8OEm8F0MUBtQaHsKHKGiUrlrLfQzB5Ef9zezOKZ5UhUxChlpy9hfvCnCkJFxowD1A8hPqvYkeAcUnv~1; bm_lso=91BE290C9E5DBF296D9EB9D884C8A0D4087DA08E8879E69B12514398D6BA3C1A~YAAQq9TOFwZZw2CfAQAAvNiWagiwl4Wka326s6NqWtc9R02TUO/lVdGQGfOz+8p/2XN85djD4Y9WmEOmdRxFwsWot8ifXQTlC0EFa2tcEJgqVzduHhT6CMUUB1VzYw7YeSbS0SxLTc8QrR8XK3Ieag5wJzEQW4gg8m94x8aB65rd2/0kMgAY6o/UdO0XNvjsLqetWpzI3QTCNZQ26skoSm/F7UCbk/MIYh/FFV4odlQN5CWj57xg2mIVEWw4iFyFuMOtyjFtVOiEeH2e/P22TZhnlxNUOITmnUUL5UIhLqFdRTU7Ps8AflhEvtz+WC6RoMzvi3yWUtziXKJca/syFh/zZGA5ZcwK7MzL+iw3Rv26Hj/WvU8Te+8E3eM/FR+lWkXyoZqTvMk6eAES9pOQbfZvZxsoQWbtGenHdBdQsk9L/bvpaagLNJj5DvndYv6TKCJzsRCp/9oljo0MvHRA9qXos4/S~1784199699686; _abck=69E9DA8732B4C324FB31C7C1E1224A0E~-1~YAAQq9TOF5RZw2CfAQAAENuWahCYVTrZdpgPkTold5vgrMzfnKoznG100G/uzXeYOqM7bVNmAkor5TGVSCujy3WZmVw5cs2Y8viMg13QfFuWbsgfrWMn9jI6TE2A9fRVvR3RnrgFk6Tz7BT7px2dzUeZe+eC1SuAk0Vr2EH4i3ZOzCFV3CBSI8gcfDtG40bR4PhGCFMCPfTCtyXWUbT9SbyjVDmknWapCQ6OuNccQNC9sX1dfzXvyeXTOrCsAYMAnAinzfaF11PvqKR3wumSBrJ9y9qrz7l9tcsxbBPo5t1s2UXR+XDPZQjMGrXWCBXR025LXVuDmPH/sJ0EGDdb8x0/guBy19+j59hTyQgaqCv48gVD4cSrzlwfcI2JLhEmai65FSj/TJeGNUVQJG1iBbwRj/BMuJ25C+6F4IIbBN+XJ8iSvLtRbaeZhmOn1Gxi/E+g8cOxESmwURe2g40dEitDZhH9PmVvJ6mQI7gthjDz03SDxhG3hEf1cRnmaA1fxjs9rAiztxLJ0uZb97Pef/ynFSv2uco1vkvWiZTmzz12T4zwrcTpa9ETDkuYYfNT7AXpDRYpjuDVs60VevEpqHoqRwfZL0uvReFXTrLDjNNSDZM30OD+ugRkvtelIWa3Ff6GdEAgQH5EbiTV6dsB7RxOkE1Ipoa09ObJZVSNLlHDsWwB7aMLtTV4cfE7nZD2QG9vERMUFqcG5FjwL4qaM3yxJTHhceWIwi25LroOhcJc~-1~-1~1784201676~AAQAAAAG%2f%2f%2f%2f%2fw3MjJ6YEXCz91W2y07+EprybjHjHzIFac+2t74iGNIGnhzolxnfXiHGcsD%2fIkvNu9ReJwyvalf5K2YaoGfaOb8gcT9zeTvLUuIi~-1; QuantumMetricSessionID=e437206e1b4a7f5aa1627e1d7fb85e91; bm_s=YAAQq9TOF35NxGCfAQAAFz6aagUKeSdw7zTw4E/hEEbukHYt2xFsRcKF91ktKJ2K1zGot9mG0uzsz+dO1CJINVuTAR6+9O/jdzoyykJohWb1XQmOTUuCpf6r4DanKg8BXVzTiNhJBpWXGGkuFGMXtYbggJc2pT0tnCTHza9pisjiT25PluEYxiCZ/ar6WFz87rfJEVUt7WOQsITKsjD8tLfhZ7J423XxEuwdARYAUfgvywbhCBHJZWiNxB6c1/HX1uurrMq8dRHxfbBlh3fA/vjw2nVWQGV2wfbj4WQh7Abj8hT/+j8QLXOILKGkm8HifX9jFI4rMd9u/wjHgsjc4DnlAh+xk82xUAKWpmAn8kKk2ZVU+K/l4fTP6l2fOsHpST50k+nldrbKPdD6lukHrfxxp0o/NZ0zUgQRw+EG6quoKAw0JmsRiO8IeROb/ZYXAK3LM3zgQ3R1pXFbttXvYTlWcinbdZf848yMV0wHPrB9m5HsTSLDcUQDgvTzK2Nj7nrt1iIil1B8f34dhpP5TxM/wg4mnfWghcfrGNOlzeoUwAYq7Djla8k3yk1bfpvfBE5QZDjkDOd5l67H+XApSEamZ/uheVIg/C2YkOopCiLHnCqMS9tFAD9vDnVzwupV3tka2Wi2gaV04HzjgRPSK5XyFA1k2CIix8q9L7x0nrfGkSm2GHikjVR5jmls7fOril/cV+WnayR3iHLZzX/64M7340f7Unzvcm5+S/PKTV+ZcY/1AY42bHsU8y5xvZuAHqRgfUSErF9zTbJg8suBJCv6sU3KNnU+aoctNFoJQ/PkaKc6i7XhhtncPWQQtkGGk2kwMJJKCuQH57KLNw3f4rViXNbZ0BlwgVeqhLUJW3PFYJzvesY8OWiCbQ92llyXSHQAMe+fPA8C8ff2ioovpHbI7rBsPdihfBKaEplrDhdCI+eOakW4R7r3Gtu6D8pvk3QUUjQjcO1VBkzoPmY8eSl5mC9bGqRgpzNGhAAZNOYl98c=; _dd_s=isExpired=1&aid=62aef04c-4515-4f15-a04f-6a9cd5943b13; OptanonConsent=isGpcEnabled=0&datestamp=2026-07-16T11%3A05%3A25.403Z&version=202606.2.0&browserGpcFlag=0&isDntEnabled=0&isIABGlobal=false&hosts=&consentId=6a825cd0-1fea-4585-8c9c-f0d0b2173998&interactionCount=1&isAnonUser=1&prevHadToken=0&landingPath=https%3A%2F%2Fshop.lululemon.com%2Fhelp%2Forders%2Fgift-card-balance&groups=TAB01%3A1%2CC0004%3A1%2CC0001%3A1%2CC0003%3A1%2CC0002%3A1%2CTAB02%3A1&crTime=1784199925398; _ga_4ZRJ21056F=GS2.1.s1784199925$o2$g0$t1784199925$j60$l0$h0";
    // let resp = req.get(url, body.ty(Application::OctetStream)).await.unwrap();
    let resp = req.get(url, None).await.unwrap();
    // let resp = req.get(url, None).await.unwrap();
    println!("{}", resp.header());


    return;
    let mut timeout = Timeout::longer();
    timeout.set_handle_times(1);

    let mut req = AcReq::new()
        // .with_fingerprint(fingerprint)
        .with_timeout(timeout)
        .with_verify(true)
        .with_key_log("2.log")
        .with_auto_redirect(false)
        // .with_proxy(Proxy::Null)
        .with_verify(false)
        .with_alpn(ALPN::Http20)
        // .with_proxy(Proxy::try_from("http: //222.186.129.68:15265").unwrap())
        // .with_mtls(certs, key)
        // .with_proxy(Proxy::new_socks5("127.0.0.1",10279))
        // .with_proxy(Proxy::new_http_plain("127.0.0.1", 10279))
        // .connect("https://104.18.34.137".sni("whatnot.com")).await.unwrap()
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
    // let url = Url::try_from("https://cn.bing.com/").unwrap();
    // let url = "https://113.108.215.122/xhr/front/trade/priority/rushPurchase/hot/branch/one".sni("h5.moutai519.com.cn").unwrap(); //
    // let url = "https://www.baidu.com".try_into().unwrap();
    // let url: Url = "https://www.bing.com".try_into().unwrap();
    let url = "https://shop.lululemon.com/help/orders/gift-card-balance";
    // req.re_conn(Some(&url)).await.unwrap();
    let resp = req.post(url.clone(), None).await.unwrap();
    let resp = req.post(url.clone(), None).await.unwrap();
    println!("{} {}", resp.header(), resp.as_bytes().len());
    // req.re_conn(None).await.unwrap();
    // let resp = req.get(url, None).await.unwrap();
    // println!("{}", resp.header());
    // println!("{}", resp.as_text().unwrap());

    // println!("{} {}", res1.header(), res2.header());
    // let res = req.get("https://m.sogou.com", None).await.unwrap();
    // let session=req.stream_mut().tls_session().cloned();
    // req.set_tls_session(session);
    // let res = req.get("https://150.139.229.223".sni("h5.moutai519.com.cn"), None).await.unwrap();
    // let res = req.get("https://aswbe.ana.co.jp/webapps/reservation/flight-search", None).await.unwrap();
    // req.re_conn(None).await.unwrap();
    // let res = req.get("https://aswbe.ana.co.jp/webapps/reservation/flight-search", None).await.unwrap();
    // let res = req.send("https://oauth.hubei.gov.cn:8443/", None).await.unwrap();
    // let res = req.get("https://104.18.34.137".sni("whatnot.com"), None).await.unwrap();
    // let res = req.get("https://150.139.229.223".sni("h5.moutai519.com.cn"), None).await.unwrap();
    // loop {

    //     println!("{}", res.header().status());
    //
    // }

    // let res=req.get("https://h5.moutai519.com.cn",None).await.unwrap();
    // let res = req.get("https://m.baidu.com", None).await.unwrap();
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