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
    let mut timeout = Timeout::longer();
    timeout.set_handle_times(1);
    let url = "https://www.americanairlines.cn/intl/cn/index.jsp";
    let headers = json::object! {
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "accept-language": "zh-CN,zh;q=0.9,en;q=0.8,en-US;q=0.7,zh-TW;q=0.6",
        "cache-control": "no-cache",
        "Cookie": "ROUTEID=IKSE.blue; aka_state_code=SD; aka_cr_code=CN-SD; AKA_A2=A; aka_lc_code=ML; KROUTEID=abbd7c96dd8eb64834cc43052cfd8778|b1f37ed7f54333e7fed5541bf6553ced; dtCookie=v_4_srv_9_sn_56D258B37C67FE53591D6FF8D62E4AAC_perc_100000_ol_0_mul_1_app-3A8b2a7e44ceb3fcd4_1_rcs-3Acss_0; JSESSIONID=6F456B51978B79FFB893F7D5B9609F0F; UAC=9fdd4442de0d42c69ea1e1eb0d24329a; _abck=7B21239CCCDE62B9C4D84590711EF692~-1~YAAQXx8WAkCSD6yfAQAAB03UsRA61IrbSSJzx4FoMM77sSG1JVVF2ZWTpWHmmvZf/KR47Sv8dkZM0uscSOlY5v/nWw+IeuzIzAJXxuqQhWQjSHzu3/0FhzJaa/NEKO7FkC8CsV7YN2Xrzi6Lruwzb028JIFoYOx925x74q6518DWGl9deQlyqmyFSHA2L+7UK1vrilc83pBUmcWI6ORxpswYLnXgPprDHR7bzrxN/lji//3rYqiVlDZIuczP25I628kgWnhGJpcYpwgrqXNgplSB/K8klNYOrodqSu7cY6m+c+Ko1JEbqlAGBdsqiNk7Os/U0P633ngM+Q8WVpkqEdIZdXaWXIOl9GneE8jq0i2PDr13j2g0f/RzlHIN+1zHmnCIv8I0pucpB7rVNBC2YQAD8q0eUCXgxEh3MlZLDzewikdEfOqMPxCGzPsmMwW1aItuOO3c/DJRDdU974qDUliIOvFzPRHMnifx7Vs4WW2Uh4b8gWWyFxIF6pPZVXn9+mN+5oaeeR5ukBxnjEUYrWwFH5SipppNFTq0bCclL1FoEAM5jHtFMtTa9mIQgFGNmVEooQwxg9A3D7agvfDQlsbQRog7t09+SnWelEPLp1dVoB9zFmP9BS9mrG+kOitWVLJGHdd9BFv+mvv6mFPnrwHKaTOE9Z15wkCJ9NnIh2Bn2Kj/F156SY+q4ZhyZ2vWk4Anb2vL8rRjOTgkR6Gz1+ctXxs91MJ/oPItfLN+1JX+St3W4Iyh0UabyohriR6moRfMIbHO4rnoI+HPrPanjUfDYa856KLI5h3Ki+BXRrfxuStwGBo1W26qYPTNOgUn9rh4sOxM1hq3t7VPyoLGk0mgWE71UPkpefA0b9D14oDT8Y6W89rJNunNIf7v/utGtU0/Y9hea7WxUpY3mf2YVnmhv5Ysy0ziS6nHqqudB33/iGB8zZqbiPrJ2RNeZLUjDz/baPuOtFzKzF3h6jo=~0~-1~-1~AAQAAAAG%2f%2f%2f%2f%2f0q8ldWPQe5y5eSRW9p5olDsqMBM7EqBVIEBtddzvrgjmZZWq0%2f2uyN46wmgeYQVcFZQ7vrVp+rSwZriOq+BZwQt3eLLsakmQy2p~-1; bm_so=2922C5900FEEAEE69BB06D6B5A4C4EC2CFC7FAE41AC22179C49EFD6A950B9495~YAAQXx8WAkKSD6yfAQAAB03UsQic1CljjX80Fv8V6QdAouJswaaPVlHOtcZkuSn7ULYC6ubOXU7T9HKG0/WIb9tbyWPA8UuZ8jfFRiVpeNBAwHTFBPTCN9g9z26WpIm7tSEktRyxJF01qpn0ulxKPX1VBrr6B9ThJFHx01+JVPmWQo5YYrt0aIwYSsxZPvxWNvuIkQyVP4v5jGhmB1I8RwUbxxAJz3llThx85P3rLqrsmoW0Rz+s1uBVX1NjIBu8DXeUXBmkTIEGJncg8w3som1aDvJV4FYaZWiM1EHCvq3Cty0PA15eB/YdNjg2Jy/ojSXI9S04N+3MPcnwFyCdG2ou/QeWfBQdjq7Rz9anj23Xb8r8bTDXvzvrVCCZdQl330Y/HVgLVVncFemcF3IvEd37jwy9kBv4Scx3ko22JBK4qGH1bFqtyNIWQipvviqxFQ9jGdWhMxv1fX0EiL1weCW5KuHp; bm_sz=CCFF6DF99871F6ADA816A490C7FF32E4~YAAQXx8WAkOSD6yfAQAAB03UsQCYbSUUNYK289Me2LnUqyYy2a1CSzbe7ROKfF2Zt+yIHH2JVKpQgJRiQNp0pKm/tAnyHGNKsTRZgmYsJMHfn/zKfcwnqA4R9VkvZefOerg+nwnVhPvvw09lXh0y7NgEa9cfAEwI35h+eYkUSjPdFKQQUKNn3AzI+TFp1Q5PLbsGAO2v9E7acftnsOIJbhxXgDvdOoddEznZghxLzU5+6MTmidcPkPvxZpjSryGtOHJTQFbSuiJM/HKPMETKoP3OsMAJRnTgDrJPkby6pyjKVhb/GuGcirNMFaXQL7Rw2M/yOfJ+rPV0uexBGhLX8KzqOVyussj3PLBAw6T50iGWvwrM+2e/UljY87J+aYpEh4pzBQilksVbCk0uUM3zYIVcck1IC6o0+x9FEo8=~3225665~3359797; bm_lso=2922C5900FEEAEE69BB06D6B5A4C4EC2CFC7FAE41AC22179C49EFD6A950B9495~YAAQXx8WAkKSD6yfAQAAB03UsQic1CljjX80Fv8V6QdAouJswaaPVlHOtcZkuSn7ULYC6ubOXU7T9HKG0/WIb9tbyWPA8UuZ8jfFRiVpeNBAwHTFBPTCN9g9z26WpIm7tSEktRyxJF01qpn0ulxKPX1VBrr6B9ThJFHx01+JVPmWQo5YYrt0aIwYSsxZPvxWNvuIkQyVP4v5jGhmB1I8RwUbxxAJz3llThx85P3rLqrsmoW0Rz+s1uBVX1NjIBu8DXeUXBmkTIEGJncg8w3som1aDvJV4FYaZWiM1EHCvq3Cty0PA15eB/YdNjg2Jy/ojSXI9S04N+3MPcnwFyCdG2ou/QeWfBQdjq7Rz9anj23Xb8r8bTDXvzvrVCCZdQl330Y/HVgLVVncFemcF3IvEd37jwy9kBv4Scx3ko22JBK4qGH1bFqtyNIWQipvviqxFQ9jGdWhMxv1fX0EiL1weCW5KuHp~1785394909274; akavpau_www_aafullsite=1785395211~id=6867e98259f53e3e8070219e7300f64c; bm_s=YAAQXx8WAvKSD6yfAQAAMVnUsQVveJOwgJ7krxU5Has3tO9Ok1j+DuJH/R0sDFWG45r5YuhWVi1dsWRjJ35nYbgoUp9LPmGEEE/8H9cXRGOoAcxvh/T/yPmFCbAD53yFpH7v9d5oijjWWaxEHBFaGlI1rmvYDUH+M4Eq0Pvjr+QuL3PlHBt7DsEk2XdvWi63s3wCQlIux2KDMTnJiy+eDG2rCh8kOvNtIUvGWSeYVvAeXRylT15Z09VXAsdkYVQNNjEbcGRjr19YewV+3CnYjsUWwblBgwXN3QQau8SIyB8hcn06/oRDsmvO0UmLsuqMjpcEKLE/tB5bGnnSLdmppSzP0BKNkfLVoS5lvf6iVN3LCIod3N5m0+60qQuYrJXVUJTHcvGYwV8jYYe1dMdHDmSo7Wigv/Nmd8cdIJ/BpDO+mjaiLGCwTxs4Ku/YEZgSFmAQA4oPVOUBbxl7f0jfxiS/1CqS3jxzXhXbb2S3pyLPMqjU6q5tmtuFJILgSC49eHrTT5q6or0Ww5zI4BZE9o9C30eC33IWbQvHGKLb3HCIaqQy9X4LM4x3dB0liqw6icUYn4uMqqaEOLIeHvLMngwdIla0pK2Hg4NwP2ePfkE+jOFQwjnaUGzhzlLB7lJxLsH3xz5yrazjwdlozil5uYkvQj36/Fcqm91x3V/EeA2m4mI3HFL5aLdfFAcWcK/cGmIBu8mzYdmyQHCsJ3pFvLBGxG3bKYtUEZwRX4Fv/3NfHKCX40ElQrTVRSL3L+HduwTb/fis/k+7dXbFNuFSQm4oKsz4LtIgN32f2KOtIWT7RQeKqeSLpyNP1w6qvKOXPypeyrq/t89d86gr6wN8goH/Q1Zha+rzXDaoo1W7dKU646yXX/+1xpJ8hv7WdjXAtBLgCw4S10q6Uuq0MS+3rMCC8gm+xvrnP9vXe2kpTvDqpiN+tBAbM+lxTgwLQ2E0yf61JGaDJvmEQw11WqPfy9jYmLFE4QsJn0pPWld7jDJYu2qCBh7Fve20ZWwzyh5Lw8JCf6NymlXnTHj5VPfrDBbKBObbSnpWcaeeOoVhDzEh2nLu1Ba1dqQtasVzjEGvo8F8zjQ=",
        "origin": "https://www.americanairlines.cn/intl/cn/index.jsp",
        "pragma": "no-cache",
        "priority": "u=0, i",
        // "referer": "https://www.aa.com/booking/find-flights/api/amadeus",
        "sec-ch-ua": r#""Not;A=Brand";v="8", "Chromium";v="150", "Google Chrome";v="150""#,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": r#""macOS""#,
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "same-origin",
        "upgrade-insecure-requests": "1",
        "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36",
        // "content-length": "5",
    };
    // let body = "ARRANGE_BY=ND&BOOKING_FLOW=REVENUE&B_ANY_TIME_1=TRUE&B_ANY_TIME_2=TRUE&B_DATE_1=202605170000&B_DATE_2=202605170000&B_LOCATION_1=ORD&COMMERCIAL_FARE_FAMILY_1=LOWEST&DATE_RANGE_QUALIFIER_1=C&DATE_RANGE_VALUE_1=2&DIRECT_NON_STOP=FALSE&DISPLAY_TYPE=2&EMBEDDED_TRANSACTION=FlexPricerAvailability&EXTERNAL_ID=SINGAPORE&E_LOCATION_1=TYO&LANGUAGE=GB&ONE_TRUST_ID=moihc76m-9tObRv5guyKslGr41r9Q93LgXyGSXb&PRICING_TYPE=O&Passthrough_Adyen=TRUE&REFRESH=0&SEVEN_DAY_SEARCH=TRUE&SITE=BFJOANEW&SO_SITE_AIRLINE_LOC_WAIT=30000&SO_SITE_MOP_PAY_LATER=FALSE&SO_SITE_QUEUE_CATEGORY=42C0&SO_SITE_SR_FOID_MODE=-1&TRAVELLER_TYPE_1=ADT&TRIP_FLOW=YES&TRIP_TYPE=O&cookie_banner=null%7CUS-CA";
    let fingerprint = Fingerprint::from_hex_all("1603010726010007220303a15bb6a000143f2f7ca5963d8e282ac452f903575f9502d5a04970b6d1815fc220a35ebde96b2873f67963043e78f1dcd560651ded935b2bd0196601d327ea50480020dada130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035010006b94a4a0000000a000c000a2a2a11ec001d0017001800230000001b0003020002ff0100010000000022002000001d636c69656e7473657276696365732e676f6f676c65617069732e636f6dfe0d011a0000010001440020efcb8cdc5672a6ef1ee6d3f52ed7e1800a44c1a93367c98dac40d366a01e7a0e00f0bac4f06171e98d1e4c34c5a8644945fe8fb539cf898cf0be5e7f9ca9e1e05489c07378454d0ca124a4146b46832ec9678748bfc1a139b2235c577657a85cf33ac4fc4335d1a4a54c786261b2ce0077af8775e0e140ad4939e52c3b21fcf2127625f1ab1e169930c6924c1f768f6e6f6daa276726decf8e0081eda0bcd030e43fedb892497a83ee2df4047acba8be320c09c9083843aa80b7e8e6a8e667dc13cf0166cdee424bd6ff3a49f6fa652269fdadd990684a59cec8d0b0b922d3a03970c4ced2d1718e5c23908142a6fb8743cbcd70106f97bc325e2073b79be07edffe6bb0f7dbc038d800b3e049f2b670ca390010000e000c02683208687474702f312e31000b00020100000500050100000000000d0012001004030804040105030805050108060601002d00020101002b0007063a3a03040303001200000017000044cd00050003026832003304ef04ed2a2a00010011ec04c03c24076fda587d8b60ccccb0f331455c8abac915c220c5aa6cb42309e3ac6dc46bc610591d217f08f83815537e5e04270ea92d7654560373427299448b36c3d7ab40d6860e69598ee2344925cb862ff238aac09e99480efc89a65b148b16ccba11f835205067e2bc46543c6627083176066da38a28ddeb96ef4a15ff0c71ace111ce1bc503348919fb64ebb57fd54895dfb271ce1c6b8c1ca0de16512d40ad69417af852a9df3118d6956ea481679ea97a7cf4771d676b8a14b1cf30b5d7872e3c2064fa175000a53e01208f0f73526227c807e789a1a589a3c6b17d0042fff614b1f90dcf2c7ab6453b43cba27462226bf13eab65c731334702c5361b3b7eb1e5379f0b6748b41014a4609fa39f43a5c8d2c812ba799e1227146a518b6516322df643e4050d6e071f4943c52a86aebff545ee876230a31a9b736b933b1ce0f0a87e0ac0b576936f7a6624696b22c181633a0f2a61c0f7f307ceecb3347004fba3880c9b7c5931bb07e70adf610f7faa431ada63f9f815f4e675bf9917dcf478d3b277a2969da7e78e5249c337bb033e23c6b9581a4649072812427f2b513249c193514a56b3cc799407ada389a7500170793794116851fb12342739b854841004847f115a1abcc4392a578a76c72c798b82b3a45abc57b42572622358cc8b2246086373e441be9bb1b738038560c6337accfa44a9dc0530f3349ead7861b6c65a427428eb99bf79926fcaa1850d9951eee6ccb69590cd1a2b8be8607b964ea07181ea939233156e6a4a3ebfa3a4d27a06dc9b09d9f910b9505ada976616e32a43db02bf3ba4ec1a2bd30265c5e26b23f0ab41168603135175a280ccd9595d646d69192a8b2c0639a33a4208079c71596972caf2ba18bdc19bc0044e1e5a61aba6413ecabfc56a89b27c33a4c4c432e177a68147d6a97ab5fb9c65ea47c5299e414850af3c1ef2212eb1885e869335f5b5be2a74c39bd60680979e57e80e9e21545a8c18f2db2270b57533f25bc75bc9a8a0aada836ee53721726c6fe1886b869c8373f22288093a3032ad28849169fabe371718083b72bdf8680ffc20375c135066859e355bdc4406b2b202818b473c87cc6dd382f61c1163c247df868eb49151be1cb1ee547915636fe1728f7ef0a7067427817a3bd4b8a2e3127aa597972c3443ae72b3ea6c4fc898bf9b38a8f8398d17d47046519393fa72056901a9805d3ff21bec6bc655d1844aec433ab790c2979f72bb2c07dc7f43cbbb64a5ba60d818287c739bb1139c04929f772f9a1163439089e6868059a46de4985281a9c1e208aa46f4639ba74dad548bfb9141c974b6c3cc0c3e65930bfa1f8a15a0b5b12ca09a68efd4ccfe9c34081495a489a71182c3806241d0b76d58a763fe11a5698570943465941981933348f8b874a4244875f30152ecc8be4bb7fc73b880f02118f0a707b36a1766c1c25a6d6b237b295cbba5476711a0cc431a182e90a7dc59396a7768bb783665f54dd500d076ac618653bfb6307732bc2c07da5c4a09b06659814768c704c1a8fc522fe4f6732b689df5b90e9f70c171e7521462114dc59d00a39a99fb9f3ca8597bdc70afe6c027b7c2a713c319018271998f81d82649e844849746015aff92dddfbc80f35132ec71870f431749ac3eb4da0ad49651a8eb2f16f01ed5e7daf7c82e66824ea2b1e43cc6068de4f4273553b35bd2f5d64bd443001d0020304bfb915fe9c27ed1bba10be5edc37d009f3a205cd55f22ab61de99221409587a7a000100", fs::read_to_string("TOKEN").unwrap()).unwrap();
    let mut req = AcReq::new()
        .with_key_log("2.log")
        .with_fingerprint(fingerprint)
        // .with_auto_redirect(false)
        .with_header_json(headers).unwrap();
    let resp = req.get(url,None).await.unwrap();
    println!("{}", resp.raw_string());
    // let resp = req.get(url, body.ty(Application::XWwwFormUrlencoded)).await.unwrap();
    // println!("{}", resp.raw_string());


    return;
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
    // let url: Url = "https://www.bing.com".try_into().unwrap();
    // let url: Url = "https://www.bing.com".try_into().unwrap();
    let url = "https://shop.lululemon.com/help/orders/gift-card-balance";
    // req.re_conn(Some(&url)).await.unwrap();
    let resp = req.get(url.clone(), None).await.unwrap();
    // let resp = req.post(url.clone(), None).await.unwrap();
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