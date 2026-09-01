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
    set_max_level(LevelFilter::Trace);
}

const REVERSED: [u16; 15] = [0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xeaea, 0xfafa];

pub fn random_fingerprint(sni: &str) -> Result<Fingerprint, HlsError> {
    let group = REVERSED[rand::random::<usize>() % REVERSED.len()];
    let padding = 192 - (19 - sni.len() as i32);
    let tls = TlsFinger::Custom {
        suites: vec![
            CipherSuite::from(REVERSED[rand::random::<usize>() % REVERSED.len()]),
            CipherSuite::TLS_AES_128_GCM_SHA256,
            CipherSuite::TLS_AES_256_GCM_SHA384,
            CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA,
        ],
        extensions: vec![
            Extension::Reserved { typ: REVERSED[rand::random::<usize>() % REVERSED.len()], value: Buf::Ref(&[]) },
            Extension::ServerName(vec![SNType::HostName("")]),
            Extension::ExtendMasterSecret,
            Extension::RenegotiationInfo,
            Extension::SupportedGroups(SupportedGroups::new(vec![
                NamedCurve::new(group),
                NamedCurve::X25519.into(),
                NamedCurve::SecP256r1.into(),
                NamedCurve::SecP384r1.into()
            ])),
            Extension::EcPointFormats(EcPointFormats::new(vec![
                EcPointFormat::UNCOMPRESSED
            ])),
            Extension::SessionTicket(Buf::Ref(&[])),
            Extension::ApplicationLayerProtocolNegotiation(ALPS::new(vec![
                ALPN::Http20,
                ALPN::Http11
            ])),
            Extension::StatusRequest(StatusRequest::new()),
            Extension::SignatureAlgorithms(SignatureAlgorithms::new(vec![
                SignatureAlgorithm::ECDSA_SECP256R1_SHA256.into(),
                SignatureAlgorithm::RSA_PSS_RSAE_SHA256.into(),
                SignatureAlgorithm::RSA_PKCS1_SHA256.into(),
                SignatureAlgorithm::ECDSA_SECP384R1_SHA384.into(),
                SignatureAlgorithm::RSA_PSS_RSAE_SHA384.into(),
                SignatureAlgorithm::RSA_PKCS1_SHA384.into(),
                SignatureAlgorithm::RSA_PSS_RSAE_SHA512.into(),
                SignatureAlgorithm::RSA_PKCS1_SHA512.into()
            ])),
            Extension::SignedCertificateTimestamp,
            Extension::KeyShare(KeyShare::new(vec![
                NamedCurve::new(group),
                NamedCurve::FFDHE2048.into()
            ])),
            Extension::PskKeyExchangeMode(vec![PskMode::new(PskMode::PSK_DHE_KE)]),
            Extension::SupportedVersions(SupportVersions::new(vec![
                Version::new(REVERSED[rand::random::<usize>() % REVERSED.len()]),
                Version::TLS_1_3,
                // Version::TLS_1_2,
                // Version::TLS_1_1,
                // Version::TLS_1_0
            ])),
            Extension::CompressionCertificate(CompressCertificate::new(vec![
                CompressionMethod::BROTLI
            ])),
            Extension::ApplicationSettingOld(ALPS::new(vec![
                ALPN::Http20
            ])),
            Extension::Reserved { typ: REVERSED[rand::random::<usize>() % REVERSED.len()], value: Buf::Ref(&[0]) },
            Extension::Padding(padding as usize)
        ],
    };
    Fingerprint::new_tls(tls, fs::read_to_string("TOKEN").unwrap_or("".to_string()))
}


fn main() {
    #[cfg(feature = "log")]
    test_log();


    let t = Time::now();
    Buffer::check_subscription(fs::read_to_string("TOKEN").unwrap()).unwrap();
    let fingerprint = Fingerprint::from_hex("16030106f8010006f40303ddd82405c0455126155b3bdccf7389d29f917a06353b12381617d68407e7cb5020672a9229e2b5c62330b776b0b71e70e5d1c676299ff4cdc9e9e042e1e3a13bbf0020dada130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f00350100068baaaa0000ff0100010000230000002d00020101000500050100000000fe0d00fa0000010001fa0020a81147aef97852bcfc23f2a4b025ac9c112fcc83d918de73099fb17b63c8142700d0bcc6b5202028b168a7a4d2623708bc1a30537b95381ffc63b18f252839d2d245d63e96f9e249cd32629ec50c1c493df5e8064dbcb7c5c3c261f42f01dcf6c6c902e5d02f63218fc8e20d2b1c94031d4265a101802683dd4a93eaf3241139f0a79ebccaeb3b746aa22fd409128eec64036898a2c57c5c59734f82384513f641f2199fe45b7c334f1e8380d4a8c1323931fe119e1d04a14dba80b05156ddf83478e2d71a05177d287260919bed2ea653b4379a8dd8b198ee669f260adaa47b017f6fc88d46678025f97692e18add0d8d0c002b0007062a2a030403030000000e000c0000093338686d7a672e636e0012000000170000000b00020100000d0018001609040905090604030804040105030805050108060601000a000c000acaca11ec001d00170018001b0003020002003304ef04edcaca00010011ec04c004c194fcd56c7026336bb31a2265627601bdd25c5461b28a65f0341b7951c33613813cc566a94d1ab96c9f36be42a4a71711a5c9f7b98f6a4a7ca958d02347f43211fda00bbbf5ba1c65a2660c0e0be6207731c602a11275749057db1c71f18f9db4201002b920276c724b5eb2d19426d28a865885b431a1e1996841b97778a80dce46a02e8548e8f87d5e6b703f692ff00222bb076eb768bce1bba5f26b514787855882b42f209f48bc4821831d22b904c3f4a5b96c2147c20dc34a25187666a063a52a7bbcd0e9650e038ff0e9957bd7bec26743b6466dd5f230a8aaa6a8b98de999b181678fe37a3eb8b4210508b80ebbb42eb4a6abd8bc2a08715ea19553970899320e4a3003abe002b804365fe20b5f30605474034c5ca4fd206c1fca9f1995aeb324ab2f668c519a0b7a438c7c16617459183315c7d422cf353c1e77442545229481143b1561507ca5abe279a0eaf1b70e1aba172c2a8909add9977d7da9c66d634092a03cf2569c15a127541ab27dab709aa3372a73b975c11acf15581cd0c76c54c67c883610256125cc747b94142a73421d0238c9e9a736d6903ea0a6413825b2262ba9b2a687141d3fdb1e1ef15756c1c638c8be37845df15526085b50f1221c7a81412af37812ea1bcb637f8d03554f12c137e3a990769d15e58968333d9e376df61bb8fad28d47b50b6eec9f71918607093077a3c9e87523bce316c5311019353ca6d00206da9499ac3d61931326627d2f25bfd4b290e4c49c8b8b5e30c67da724602f4165778b4500756af976b3a4ca965b780c3bf2831ad175e5c67323a65ff037138f4c841ba13d2f5a5d7a5722d03a9db0e35ee0ec249be31687557541d8132f1106caf05c76526cf703817297878264297641878dab919c0009debb674c68495fdc575b9a34b10c80f46b82c769a8d651366182bc7f437c2a696d28a77c5ab93f0093cef056ae70b93436d286faa2c916a46210305c97eb2fd9b56c9e211380ab6ffe42b45b044607e3bf8ab174d3b62f5406a84453ab684446f2c53d46367d6a2756824b72b6682e195b2edcf9bd6d1c2cb3fa34e8c18e9212c6f0977e8ff04398108391a828eca91cd155993f58a2818197064c11a39a756abc595c1aaa07408283d232595959a2a2ba0b2cb7b30402b9390a14598c4b620aacc8cb040c021cb994d90016c0953f0a35b5b91395bff99f1abca44c11a0d21c6114a4247250bc583b9a40b74cf2b1a968c78a6d92616dd269b9540d0e230ef6a59d20388fc2d38a88e59073e4aa826b6953fcb186d95e2d92b27ee79ac1fca316a3506239b379627f025245ac1a3e4088604389cda3c1bd85fabb97141209f84fa0918fd14ac1585bcddca8a6ece44811956cc1447b498b8ff6d17791213fc6934eaac61399999dfef6b583f5b172204ebc71bcc0f044c4d81ed398a34af309e81b0dcab180890a1aec792e51c52e3f885e7bb04692ba4929944283060877b709280185cb406e9e009d1fc7bc3db08fbf24471214cecdd73287c006d06aa687d20b6e7122d809a3e476608532a1c199b82f96aad6715ed0062113a403ceeba2a00b741218bb1c6c60501a75b458316f8c390dc43b77754bf86660c74926ad9813a63c2d6af7c208332857f30ac9755c3a98da212fd2e203e0f0f7ada7f547b8f6f7b951b2d26f1e5fdd7239c5f2b8b4efe8a28bf048d87fbc1d794c3363001d002086fd603c22bada7ffb7960e7e4a14060955ef0002eeda1d0e18166c46d6d1c070010000e000c02683208687474702f312e3144cd000500030268327a7a0001001403030001011703030035265ee308769943b11395aed49c4d8fdefe87dca2faefda9969c582f94e851083f215128cd86fcfe04487c351de672df412255ea3bd170303051407d10558770acc21b352ba67e5664ed6f80ed7ea489d5273fc89cb3fac07b2e5ed3e48b22e3f5fe6eb348c4a204be8d2b6591967295d0f22b28b5e01a98379ca92db8603b0274be5a41130e13b862c9a776f3c58a1ec9b0df8827ec039aed99e8e4e8332dfe681282425134dd3ec3c116c027e734b0521449797d91a8ff7280699239c644de1d23ef4606567eaa6195a07a74d62cc802d41835420d6945fa3b865f0b94df1a2c5f08dab4ee4a2309133bb1810627f67f43a9cd3da1c1cce36da9e2e9863e3a628b1422563b01e7763166f6136e3ad8702c0064963d7074fc5e88ac49f62855e7d5d0750b0c9515fee281412767e0b02e425c0da62f24877ae0057772a950d06305b8abf1c3d79dc9b847598d7fc7fa526e41221046a7a5b99223346d69e1d7098e1119f325c7f38eb0d9cec8a667e14e9859c37e10fccbaed1aee16a4e57f13630edf28930bf4c895fbf7967df44186ea8bcf83285311fd251efbbdb3f92c9f49b6b7aae20492103e0f175ab26c61a0617270675b2065bf36660b0fff7c3c3b98c0daf6628119c7e3010c4ca69ab484eefe7ff2b032f606e74374527c9703ad35d4450868b1c7478aaa62bd87c9b557dd5063385fa6365e26582ef1a7c37416dec45533cd4e50277be66f8884d09a5bc77080faac14efc7c5e26bd65edb8971a3ffd5c9d04fa2c7fbba7d1d06d573399b535a19e8a2238a182fbe30c3ede0ca9900c34f58e4fd75121ff583163388a22cf0c19449746c6a570a660f4608ca3e587d69a2c35ca6b7eb0361de4ec7d9f5a35cd64df33d87feb7014f595204345df83bd4a6dd2fcfe916192d32251df711b24a3979c4a82ee3a30691534929ab42647a2aa0cdb0b04b322c5120033c9265673c23ff1d76a88556c3cb324ad2fe245835ba80376c42ea9cfabe961efcc30444fdb6720d65d9226738cc701106aa4e4c151bd5c4aaca81711a07afe706fb031609c06388cffe8dc1080eaf074fdef7fe7d6dca5538549e3e819b59001dc156303fbf56a7da531d0f3d33d4c8b66af988bb04e175eee521162a468944e669f299997847d97dd3a1329bd505fe6da1fe1583be7d44e3504eb09659d07e6d71156c27ba8e5f80c41db54d7cd1c44db0119133179f9998480cf0323dcce2d7eb35044fd157d944b7e5dfd32017a283ee195a619ad2d0b30e66adc0c877029b177d13a12e7918a97b8d2a42e8f689c31c85f10f99bb7f8ea4dbfe2c6b94283b9d030ae71ebe045e9a078261ee10a3b6d4207106141fd4122bf20349aed1f5f5c7c3d38b5e57515b405cb7a6177fdff6691abf6cd06740a2f3ee5602b66ad854dbcc928d5e177d6191660ede9483217c1fc7637109bc1337bc199dc3124a0b07c06c50f849f7c940429b2911fc1bf0a5a563e1ddadbc65c86c281aab7cac0974407c2c140d75452466e9a33dd8c8a47d0ce5335d043cbe0f6eb1d31ab7506ab732d1a781e7f5665ce0a346470d76d4d0bca247a5d9fa7ec66b99ac8c2faade0ef935d2f262bf94f5e5b7e1939860b6aae1ab1062774fbed14177cfbf833cc4a6ad1853195b57fd867a27eea52c94790d14fb3d9e1b4ddffb2ddd182657723d69f8ffb56e01ea9a6c458808fddfd82a3604594da88801548750a6516f2a2695cc3ed9db60c884fa72ef1773af7dc26ad1c35f121770147d64fc8827aa70769fb1cb71d7d08608fc76b8a187bef5e309a65695ab90e4fc65008c1ab7dcaad9c90393ba860c7b8fdc8d3b91b7bff41a341f8366994cbb8c29139adc0076961323999c8a05dd6b181b5d4a3ff08c5ba3bbee7651f4ae5bb5d20f8ceaf3a6da92e023", fs::read_to_string("TOKEN").unwrap()).unwrap();
    let mut req = ScReq::new()
        .with_alpn(ALPN::Http20)
        .with_verify(true)
        .with_timeout(Timeout::new_same(3000, 1))
        .with_key_log("2.log")
        .with_fingerprint(fingerprint)
        // .with_proxy(Proxy::try_from("http://36.150.202.148:10951").unwrap())
        // .with_mtls(certs, key)
        // .with_proxy(Proxy::try_from("http://127.0.0.1:10280").unwrap())
        // .with_proxy(Proxy::try_from("socks5://127.0.0.1:10279").unwrap())
        ;

    // let headers = json::object! {
    //     "User-Agent": "Mozilla/5.0 (Linux; Android 15; xuanyuan Build/VKQ1.250106.001.OS2.0.5.0.VNECNXM; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/128.0.6613.88 Mobile Safari/537.36 moutaiapp/1.9.7 device-id/bc823b4ef4840826d5df6bb059410d36 BS-DVID/UkGLUFZAqT06gye-0nF1683DRwZ2yujoY3kPcrdz5Ng9JA6i5g5XWsmJpNTq7PvYDiiCRTagsZn2LANM-RoIhDQ",
    //     "Accept": "*/*",
    //     "Sec-Fetch-Site": "none",
    //     "Sec-Fetch-Mode": "navigate",
    //     "Sec-Fetch-Dest": "document",
    //     "sec-fetch-user":"?1",
    //     "upgrade-insecure-requests":"1",
    //     "sec-ch-ua": "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Microsoft Edge\";v=\"120\"",
    //     "sec-ch-ua-mobile": "?0",
    //     "sec-ch-ua-platform": "\"Windows\"",
    //     "Accept-Language": "zh-CN,zh;q=0.9",
    //     "Accept-Encoding": "gzip,deflate",
    //     "Cache-Control": "no-cache",
    //     "Connection": "keep-alive",
    //     "priority": "u=1, i"
    //     // "cookie":"_EDGE_V=1; MUIDB=184C10AD397866DF1A1607B038566708; MUID=184C10AD397866DF1A1607B038566708; _UR=QS=0&TQS=0&Pn=0; BFBUSR=BFBHP=0; MUIDB=184C10AD397866DF1A1607B038566708; SRCHD=AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF,AF&AF=NOFORM; SRCHUID=V=2&GUID=EB7B9E5DE58F4D5690F6904732C24C7B&dmnchg=1; USRLOC=HS&ELOC=LAT=23.384721755981445|LON=113.44195556640625|N=%E7%99%BD%E4%BA%91%E5%8C%BA%EF%BC%8C%E5%B9%BF%E4%B8%9C%E7%9C%81|ELT=4|&HS=1; _RwBf=r&r&r&r&r=0&ilt=10&ihpd=5&ispd=3&rc=12&rb=0&rg=200&pc=12&mtu=0&rbb=0&clo=0&v=8&l=2026-03-15T07:00:00.0000000Z&lft=0001-01-01T00:00:00.0000000&aof=0&ard=0001-01-01T00:00:00.0000000&rwdbt=0&rwflt=0&rwaul2=0&g=&o=2&p=&c=&t=0&s=0001-01-01T00:00:00.0000000+00:00&ts=2026-03-15T14:03:35.7211444+00:00&rwred=0&wls=&wlb=&wle=&ccp=&cpt=&lka=0&lkt=0&aad=0&TH=&cid=0&gb=; SRCHUSR=DOB&DS&DS&DS&DS&DS=1&DOB=20260315; _EDGE_S=SID=357AA105805E678827ACB618817066E6; _SS=SID=357AA105805E678827ACB618817066E6; _HPVN=CS=eyJQbiI6eyJDbiI6MSwiU3QiOjAsIlFzIjowLCJQcm9kIjoiUCJ9LCJTYyI6eyJDbiI6MSwiU3QiOjAsIlFzIjowLCJQcm9kIjoiSCJ9LCJReiI6eyJDbiI6MSwiU3QiOjAsIlFzIjowLCJQcm9kIjoiVCJ9LCJBcCI6dHJ1ZSwiTXV0ZSI6dHJ1ZSwiTGFkIjoiMjAyNi0wMy0xNVQwMDowMDowMFoiLCJJb3RkIjowLCJHd2IiOjAsIlRucyI6MCwiRGZ0IjpudWxsLCJNdnMiOjAsIkZsdCI6MCwiSW1wIjozMCwiVG9ibiI6MH0=; SRCHHPGUSR=SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&SRCHLANG&V&SRCHLANG&SRCHLANG&SRCHLANG&V&SRCHLANG&SRCHLANG=zh-Hans&PREFCOL=0&BRW=NOTP&BRH=M&CW=150&CH=769&SCW=150&SCH=769&DPR=1.0&UTC=480&HV=1773588648&HVE=CfDJ8HAK7eZCYw5BifHFeUHnkJGC6_lT8f9GeruXx8zjPXuk-5GHkofYMoFErMkT8CTKKKsSt5O2HyGmjLyCEXbEREUmwCd8ZBlYMLSDZu1wZ-EI1LDuyIiI1tkP6Usyicm601qX3aJVYqVWUBn-t6h0ZWLiftm4aS627xFj1fE5PD-85i7BWTkhqG0uvaYzuSgB2A&BZA=0&PRVCW=150&PRVCH=769&B=0&EXLTT=7&V=CfDJ8HAK7eZCYw5BifHFeUHnkJGijeRjCoaCMaAnmznMvdEg2GXY8647Wb-7wnHNpePKXRO6KRQ_0cQc-onivd35uV-p-4g0MB0V_Z1ZpW-QSJe9zbPUG-Ks-kQMjzEl6GlLo6N0ciP51vkQdR-P-lCUH58&PR=1"
    // };
    let headers = json::object! {
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "accept-language": "zh-CN,zh;q=0.9",
        "cache-control": "max-age=0",
        "priority": "u=0, i",
        "referer": "https://www.coupang.com/vp/products/9694611384",
        "sec-ch-ua": "\"Not;A=Brand\";v=\"8\", \"Chromium\";v=\"150\", \"Google Chrome\";v=\"150\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\"",
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "same-origin",
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1",
        // "cookie": "x-coupang-target-market=KR; x-coupang-accept-language=ko-KR; PCID=17872459817849003608749; bm_mi=F7C64E8A7887F6DD80016A9188D8182D~YAAQj6UrFwrLgR6gAQAAJ3MpIADNYHG+CCLnd611+YRVIKHa1zxfI9OWRB8qhZCpfAvDKn40J9n5ZdsKRchTVttFJSjFB8XXO786NqvWJEVbWddLT54WGatIjWLhd72jOH8/+6ltGSaO2795cXG8IwKXchBZUCRFBh2tYCii8pmHk4DHwa8GUMn6prJ5fmEoHcLR7Irg51TRWB1K36GsXZnzBm2esPCGykyYAVCP+lqrwFJII8fd9ww+HBZn+jCsvwUAJQAFB3qWYMP69y0xe6iaZV8X6NpsPWSr/8V/qd430UbIqxbOyBSxIomfy6Yf6QSU9zjbtAvEh+bbTBvA7aC0VQ==~1; _abck=B78D35CF4F83A662248A7F2D5CEA5368~0~YAAQj6UrF9Yfgh6gAQAA2/YtIBAqEyW/t5ZPZv1KelyXJDyQ1WWMm1PVCDonOLbqx+dARiC9vqYF1NKRe/JwqMl5Zmd7ME4boTgU2jKZctfYkF5lT1p5BxbIK1jng8HV2I9fCShPvzNZ008Y0dJnYtFk1D8zka99YvhPXVCS4CVQ8ON/p6wuiJ+JVacFN6yeqS8doztkw5xTTiroojZV0r9vOine7E0u0myBdYsL+8GeiNQOxeibpjlN3A9XH/JFiURzt91wnFvayJw9DYLwyOw1yj/he21vN8ncZrXA+QsmBMCpPUotnyPzUSfBLQlOMZzTb2DhYiEveZ64WkytNfqk6bf75oo9hBhpuUk0VYlY/6aHXOyboTtgc0FtCAAhUsJGh3QofzCPm1/nb9kkSFjQhA3pzG6qQHhCWWlB4Gbq0Ugxo/6uXxUw6evfpWs+oKuZlQ6HVCDoOXzEM44mdIaZKQTtDWmkTP0B809/H7nmvmis0dzTLTYC4fj/WgZTj6Ei8i/cpi77R4tJCbup/yJZNuUexsZ2ELWSmARAByONSZNsf8/DtCbTezizH1JO6pA8VMx6ogm5MOy8Z6KblbE+XFUbAWBm3PFZnMuldIpD0smJkhKPxr70DNpKxp2H/7eh3iWCXeAVz3/pUq+E1Wc1B1A=~-1~-1~1787249580~AAQAAAAG%2f%2f%2f%2f%2fzOq7RjTdGT75tFxnB6wMxJgI7x2qCoKowDxOhMg9i2FOOouhvpIfGHiw52N+VgIJSMBBzvd8q7Pl%2f+g7DMKG5HIDYQ5%2fAXxM%2f6g~-1; ak_bmsc=1A5CA1DF18C96631131ABF16E428BC1F~000000000000000000000000000000~YAAQMQw0F+NmjfufAQAA9RMvIABQqXq+5aHoDi7T+NLGE0qO90RvOdRdCFEO03338oGMvcfJcqYHaEO2dxAjd56Bwi+ScyRYXi7EjGYvnOL0pJRE8KxrnItEdcmmYU0yn08oUj6DGi7upxyiM6YLGbWH7DEJBvgXOO/Hao7AtfOrQpiSj8NDbLBKFVYLmqq0h3SZJK48TKHelupD2ZxPxjrJo+e5QjKxK8vzb25srABS/olWvOkBRshzb9xztTHQ6NjRdUxMKFDl7sMlGy9+EvJYvQ3tA7v6QoGHY8W7ZLMxPJOmh2zEWWbtbdRmd5b8DeojU21GTFNHVln61mc+SGxyiEihRV0vThRgWRpZk3senRp6paGXEY5sdi7UU0Flrh9hSyd8+yssuH/c5ZgjrAMuel4VUNgvOv22Xp3xBM4lzkbGFyseFnN5iYtITlZNeL57aTpAY/JIpdB+lpd3pCdmhGPRFJEXUMndCocxrVk9dHAycV+4NOd3yT7jxlR3W2FH+hRD1t66+uiW; bm_sc=4~1~690404244~YAAQMQw0F+VmjfufAQAA9RMvIAkQ/wp6kUIxWG5sp8wV5H/lJ5DkXnW3mEMc5IPEF/7wRU5vlQObGZMM2WDfZpIzWLEGuqbUzLVbiX9/V3lIOP0iqj3BxBbWNm7MZ0uNNKwLIwKKeAqgZoMJY2IJ6pNZVxKmLYcE/LniBwHOx0nJcaxbRw9Sumu7tBpq3fFx3GU86ZdLpaJ6nwDKSmsCHD6OP4ULTOkkBJYe/iKYgOZzYBme6iPOreUnDBNujOqMnEIsTLxENWuLa89dpRU3ktWaV9FHwQM43AYkI1YbI9TktA2iZWEFaKVOGLmm1QBOLxHueJxi0+u0EykirGb5RiKYq2wqR/0kcO0HmGRanyKx1kTJePEzTyd3Qq1kIGdwMO0nSU6zvJzfaH1MDQ7hHRYbvmcvDqSjMFdXWFsif/C1OGK3Uh2PQnPLEkEVHeN/t6eXjdS7jyBn4ix+zW/qnvNlCHSDsW7OHhg+9DREmZn//itZ0FmdoPGB4nEW36pYc67Y0JpD90E2zOVes9keUJN/5UjA/03Ul63VPS6f8eiDGyQAp1oT5B9UzfdZk0CjHiwhVn0g+TeC01RdBNrmczMPLpFpchG5FYX3d9TYR4QeWDU76U0R7RxJaXqPwWj8m9Ozn7azN0fXLViy9n4NhqY=~0~0~0; bm_so=FF801D3AF15FC270A6F2A0A271EC3F97AA41613D674107B02FC8DF69D1E8EA2F~YAAQMQw0F+ZmjfufAQAA9RMvIAjr9BFFOxlX/Edwqwy5TQo3lZTLxwIWz9ltVqn3YUIjWuoJh8B7poV+3bdZM67dj6Pn7Gp/+OpzXZriZ1lCyHSkAbeuqLWoe7c+F6Z/1CuzEpmwnOTCTEAQl8ltad1294ph1OZWSx+TRMB+QqQoxpHHaLjLiwmH0SGAmufnx5X4WYo5bStmquu/8iOhvWxlI7ovguZsYhrv/4/aYV5Vhx33t6LQGx0Awnhqfe2QFa59k0LwvR00wlDjdfcxaZlsY1kH/jPRWEGEsGsQ6OxdTDwuY2TirR+mWP4fR624eibogcDt3LPj5s4ieBMaKJ/KLL2HGlAWehWefyFBDyxyYVT4s86yLggwAa/5sgi91Bwq7Xk7eiiYZ84E6dk9QgaGm76ZumSLh58+9UeT7Y6RRgngeTDCHkWUmct2+cyxPuZ0ZVdKpRGGyRH4CnHKb+uuAw==; bm_sz=0EC0FEB9F0263E55B081C7FAFBA9DED2~YAAQMQw0F+hmjfufAQAA9RMvIAAOGeLNEp40aXs9ilifjpHbgR8HiJ7pd7IXedBY20DGdC49PRzvtlCNm2+S8cJMxDM2TMEGKaMnC7D6/EWGiapukM5FDEqLgfIgbV611QFygngobhNbIgERTT+iCRd5uliBbTtdwE3JN+ViO/Kto0eqpLAsHTbiIFRIoUo1ThGbNYFeVVBn3zoTil/NlEs6SEPlROOKdyd2+f2LAYM/QY+fEjZaB/fhTOg5EGEfKawCclKPV7SeleCgx17mcrBPyBGj9iBjJkLcwi3wk2F7R2c6KxHRhOGF2klxtl26X4Ly0WBoErT9gE7Y61mX3dEHOWU4nL6ANhe3o7oEbDGnxYnUq21jWUU1aNkKe0NkcmIt6vgCYJAUbCOFalwFbE+WjoJWJXrtqVFiwi9gtJqisKJC0CTTBS5IG1/nrRC7Ue+7n4bwsteE0dnGm+c=~3486787~4469042; bm_lso=FF801D3AF15FC270A6F2A0A271EC3F97AA41613D674107B02FC8DF69D1E8EA2F~YAAQMQw0F+ZmjfufAQAA9RMvIAjr9BFFOxlX/Edwqwy5TQo3lZTLxwIWz9ltVqn3YUIjWuoJh8B7poV+3bdZM67dj6Pn7Gp/+OpzXZriZ1lCyHSkAbeuqLWoe7c+F6Z/1CuzEpmwnOTCTEAQl8ltad1294ph1OZWSx+TRMB+QqQoxpHHaLjLiwmH0SGAmufnx5X4WYo5bStmquu/8iOhvWxlI7ovguZsYhrv/4/aYV5Vhx33t6LQGx0Awnhqfe2QFa59k0LwvR00wlDjdfcxaZlsY1kH/jPRWEGEsGsQ6OxdTDwuY2TirR+mWP4fR624eibogcDt3LPj5s4ieBMaKJ/KLL2HGlAWehWefyFBDyxyYVT4s86yLggwAa/5sgi91Bwq7Xk7eiiYZ84E6dk9QgaGm76ZumSLh58+9UeT7Y6RRgngeTDCHkWUmct2+cyxPuZ0ZVdKpRGGyRH4CnHKb+uuAw==~1787246351253; bm_sv=7DADA63E2D6E36AFF224B46583ABA1E6~YAAQMQw0F0pnjfufAQAAuhcvIABM4aU31cxcq8XbybtXPmpkrhzfyuO1dG0gEjQiQR6zqdjJyBsIPaWowjp/Sqbl14Tlae1YB1Cwg6AH6GCQ8lLkqyvLeSFo7bO568C6DW5jgTujsQiPFiodn2XkYjd/u8PI/8fSOcQUFISj1U+Ys23c24RsAzBBAbh4NYARBCxdXhYepCUF4K0i4wrKHZEB/X19O7MiacUqdmWhUmvtM+Ei40uljpMu0/Bu+/CnsD0=~1; x-cp-s=YzE9MyZjMj0xLjIuNCZjMz0xNzg3MjQ2NDEwOTUxJmM0PWFVNW9LMmhKY1VWM2NIbFhkbkZTT0RoeWNXRnJjVk5GZEV4eVFYTk9OM013VDJGTGJVeDZkM3BJUzBsdWFqUm5TME54SzNGeU55c3hjR3BsWjNWSksydHlZbFZuZFhrNGFHZGlaM05LUXpoMGNWUnRkR3hCT0VkdFNrTlBhVFJSVW10Sk5GSm5hRWRrWjBwRGVFWlJPSGxwTlVOT2FUUm5aa2RTVFVwSGFHTkNhWGxKU1dsVGQzSnZTVEJJY1RZeVMweHhPSFp2YVVWb1NUZEomYzU9Y29tLmNvdXBhbmcud2ViJmM2PSZjNz0mYzg9ZTRjZmY5NDcwZDRkNGI5M2JkYzM2ZTU1NTNiNmQ3ZmUmYzk9MiZzMT1uU0IvWVMxQlF3T28waFBJdVozbTF5d2dPV2RYYXI5dXpna2J1K2tFTmdVPSZzMj0xLjEuMA==; bm_s=YAAQMQw0FyCPjfufAQAAK4cwIAW4dnuXqeQ5lnLFfUhaZ2R6K/S8oo+JjnUbR6BVm9hM3zI0AOXEDgGcpJOK5xbarUFEzMqyUuv9PN9rEuGgF7EtJMBnVmlFFqy5JVIbIANGjQuTXu7YdtEWYSeEaTnxnKbwK/ppta0t3yY96D4VBBOWrZeNs8J/lsWzNzGEkZpfEZ+xAWhXQHVM/rWF+rqamQzdCCl4ij7BgnPWWiWYPGQluhZZCn/MUPXi8eugzVirOE9kXgu/iQjv4ZcwFYXAtEHWT6BZKLvokjEqhQyzYceuR0HV0r85MKzJ7njQAyWzz9D5di6nJ13AIqI2jyhiZHUoW747tp3yrvVRdkPXp99DP98oa+dJc6XdoP84rWKw7wHjqTj6BhcMrd41UbybUqyKMM4vWo/Bi0LEhUT9fJSzUbXDTH6xBDB8kyuCNZ8GuisfxLTrV4fKNgvXY+oPMenL/iLrLXttJT0ukxFxDcUD2EDbVr9sGMLkRJi0zm9DKHLEtg3GEG3fRprH1c3DvIxP0iIIOYLYGfVxBilcrNqfw/6/yOBf5gJaQJqR/ArMiO488fb3wb6F+hDhzTzQRyVF3SFb9lBzJA1uzbjkEZh8vn49ozCRzohR5vxqlnP7wuzicPrvDo4pOAsrlF849CPayORPQzDbKhpgk/mdDkBrHRVHRQFPw8YrtVcKR4X5zMBdteNQa2IXM0fYSU1q3kVXhBqdKaQhCti4pAq1OlCnrMwe5MbRwRqIo7sNytzu6zeoYLUeKFCZvwkGwzSmpmbrxFKeruvSt8PbU4u8KoM/1AaAlDRsT8M1eGw6gYmqhji88Ejboh+AKX57UPHU3Ud67d71NO2DtC3V+896eSy1CF5YogcECZhPyyUq4ND2jyswqpKJpaWy4Fephj0uPhPHjs4R79vCUnPYft23roOA0g4eICfWH/heZmiI/X/UbC8QUxgRpFJSMUH5zsrgPXsujjOIwgYSvCFVTup4YQogM9VIzc8SR0hdygpYWRuGmDYJvvPnlI6mw56r0+Y1MLL8hzkG0qDOdQs1S5Zlk07y36b3ZT6sEuwQnyB8CQIdoflTPAgFs0qKqVVmypijf50c6PrcoSMlDm7HWfMcV8VUAur11iy+oAWtJzZ/tA8=",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
    };
    req.set_headers_json(headers).unwrap();
    // let res1 = req.get("https://img-s-msn-com.akamaized.net", None).unwrap();
    // let url = "https://ts3.tc.mm.bing.net/th/id/ODF.dsR0yzVOEBuWxCU9cjAM4Q?w=32&h=32&qlt=96&pcl=fffffa&o=6&pid=1.2";
    // let sid1 = req.send(Method::GET, url, None).unwrap();
    // let url = "https://ts3.tc.mm.bing.net/th/id/ODF.pnhuF5msYDWgeLYHsiLTig?w=32&h=32&qlt=95&pcl=fffffa&o=6&pid=1.2";
    // let sid2 = req.send(Method::GET, url, None).unwrap();

    // let res1 = req.get("https://docs.rs", None).unwrap();
    // let res1 = req.get("https://www.rfc-editor.org/info/rfc9001/#section-5.8", None).unwrap();
    // let sid1 = req.send(Method::GET, "https://cn.bing.com/search?q=http%3A%2F%2Fwww.oiedrani.com%2Farticle%2F996e199002.html", None).unwrap();


    // sleep(Duration::from_secs(5));
    // let sid2 = req.send(Method::GET, "https://cn.bing.com/?scope=web&FORM=SUPEDD&pc=U531", None).unwrap();
    // let res1 = req.get("https://docs.rs", None).unwrap();
    // let res1 = req.get("https://www.wireshark.org/", None).unwrap();
    // let res1 = req.get("https://www.coupang.com/np/categories/400536?eventCategory=breadcrumb", None).unwrap();
    // println!("{}", res1.raw_string());
    // let res1 = req.get("https://www.dickssportinggoods.com/p/2026-topps-flagship-football-mega-box-26topufang4p4ib5vqjhq/26topufang4p4ib5vqjhq", None).unwrap();
    // let res1 = req.get("https://www.coupang.com/np/categories/400536?eventCategory=breadcrumb", None).unwrap();
    // println!("{}", res1.raw_string());
    // println!("{}", res2.raw_string());

    // let res1 = req.recv(sid1).unwrap();
    // println!("{}", res1.raw_string());

    let sid2 = req.send(Method::GET, "https://cn.bing.com/search?q=3516541635&rdr=1&rdrig=4B500EC883E54B3881736EA98E8C2AF4", None).unwrap();
    let res2 = req.recv(sid2).unwrap();
    println!("{}", res2.raw_string());
    // let res2=req.get("https://docs.rs/fluidattacks-blends/0.7.0/fluidattacks_blends/",None).unwrap();
    // println!("{}", res2.raw_string());
    // println!("{}", res2.raw_string());
    println!("{}", Time::now().as_mills() - t.as_mills())
    // fs::write("data/coder/chunk_gzip.bin", res.raw_body()).unwrap();
    // println!("{} {:?}", res.raw_body().len(), res.raw_body());
    // let res = req.get("https://117.89.181.21".sni("m.sogou.com"), None).unwrap();
    // println!("111={}", res.header());
    // let res = req.get("https://h5.moutai519.com.cn".sni("h5.moutai519.com.cn"), None).unwrap();
    // let res = req.get("https://aswbe.ana.co.jp/webapps/reservation/flight-search", None).await.unwrap();
    // req.re_conn(None).unwrap();
    // let res = req.get("https://aswbe.ana.co.jp/webapps/reservation/flight-search", None).await.unwrap();
    // let res = req.get("https://oauth.hubei.gov.cn:8443/", None).await.unwrap();
    // let res = req.get("https://104.18.34.137".sni("whatnot.com"), None).await.unwrap();
    // let res = req.get("https://150.139.229.223".sni("h5.moutai519.com.cn"), None).unwrap();
    // let res = req.get("https://117.89.181.21".sni("m.sogou.com"), None).unwrap();

}