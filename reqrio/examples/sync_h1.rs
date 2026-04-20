use reqrio::{json, Fingerprint, HttpStatus, ReqExt, ScReq, Time, Timeout, ALPN};

fn main() {
    let mut timeout = Timeout::longer();
    timeout.set_handle_times(1);
    let mut req = ScReq::new().with_alpn(ALPN::Http20).with_auto_redirect(false)
        .with_timeout(timeout).with_key_log("2.log");
    let res = req.get("https://bing.com/", None).unwrap();
    assert_eq!(res.header().status(), &HttpStatus::Move);
    return;

    let fingerprint = Fingerprint::from_hex_all("16030105b7010005b303030197f07eba2317b09411ccca32c3ca4520c7a4d427d4617d3219e9173c21567b207ef647003b4151c1a8f1f4e72b3e2821b98a5af7d7f7f1cb9912965dd8be2e620014130213011303c02cc02bcca9c030c02fcca800ff01000556000d0016001405030403060308070806080508040601050104010017000000230000000000160014000011736730332e636b636c6f75642e696e666f000500050100000000000a000a000811ec001d00170018002d00020101002b00050403040303000b00020100003304ea04e811ec04c0f0a71f3c99832eb733b81ba2c01c0807b94c4877963bd3ae5d08af1d02cf0f719337f948cf5938421c52ae8baacaacbffe32cc91abaa8f89a2f5002f7029102a02ae330255eeda21a8a6517ee872f646273b97ad094c6bde77a9829c6eee7ab9a7799823c3a7aed931dda20cbb2c45ac58133ac4351c38438d4b5f2dbac976b8a955d153bab3769657bc07f51f0715ab9e561b12496aa02238ed2b32816446ba367074930d8efb0cabd48387127d5bca9bada07acb29c9fe1958c6e0cf2b6b53365626898c32fcf23b3eb11b339abbeff313c8097263382d42b090d8765bd262a3b63a45dbf5c04ab94417a35dad713293d1991802ca67da9ccc527f6ce629df08a073b4193e372898d23f04c14bc7053e1112707f2c187876b98ca91aaafc0bcd61806b211d99e60d1eb8bdcefb04bba3a0e4ca1c7d4945c7e5567aa5025b57cca2e80991892debf11a4b067136581d3ed59912460be9f24941c34e88d4661cb09f464097b9b573e8d349871b0db3a513e3c61983a5c5193850f400226ed30c17a6b615b077564647ae6ab09f3cc5cbc74cc78990f20311f2eb37f9e077215098c64335a1e25fa9876f3593ccb9004413731cef6c09472b507d4395b23a242f723843601bbfe4c330ebce51da911967a85ad1a5792999341a117c407c86a49461887828b818bad9c600db50a2ca4ac86199394031afe9a28677631ce49785cc782818a29a14c2375c4aa79998e241207cbc603a32b142843b73d52ec1b92f7b1aca57817ce5d4109ee8734617c8e69147ee59252838a1639276adba5672049a661146f7039dcb18a93c0b634c87cd51fc2a187935bb5062b4d0322596c223a49c052bc8fb12acfeeb428002aa62d660016b9460016f28984a175890a5d67c74466d44117184d219ccc27d3d551de595111f2b185e929e324954a3568e6dd63e10ab4e5947185df02f648a9a8af436516aa813679b787b807b003245a796795cb91453a8482283fa66aa66a3837f4a6ee2d2340962a2cc9c4e62c6033947605ce72e0046aab962871c9850bbeb0d8d14c47391bab9a59c3e35c1e47ccb8a0c8ee855cc99ec64a993579d993f9e12711d16aa61aa2a915c0baa6acf3df4c9521a4dcd4c002ec56bfb4c7b5116ab06f1859d857c939ca29fcb6e23c93d6975ca6f49a6c0d1a5246bc8894893914122c3cb3220939e3aa916358360386ba76603ab9440916bf585c5537f26b77f2e7459bc707ee47527b54b239bcb58254288e75a927673ae74050eb35280b16369aacb85da861302f19fec1c7ac17185367b6a7c773f6b1abc0bb685f4cc518153c3a76c4d89795444f493adf373b40a92e9f18eaf224d90d48f0e6a7213a2b860a36f585b84ca24a33ce72014ec43dc046b0612922eb457a24049655a664072b2832314a6f2ccadf7b862692069d269cc62351bd279d683068327b668065084890c3f3c04d959adf2903ad1424a9a60b1cf3aa24ea81dbcf71ed8c82bd3cc271dda799d2b0d2f208163bc7f8b66a48db9a4aed10eb705690734cfa575b4deeca83619524aeb963e9c2ee81c7f51d91efe0a1f2f79a332b02bbe8a55e8625025f387b5a27982a78296f4c172720606073b2ada9bb924a44b941e81f90811ad449914919c6dd9a9562c2a99c5833bc010d91e65fe3ac6022cd7e274d3e9a787bbef8ec3507c25b8fa29475e235fda8ac4a6af9f31001d00203ac6022cd7e274d3e9a787bbef8ec3507c25b8fa29475e235fda8ac4a6af9f311603030046100000424104ff635373fbbfbc37444a2026372f57fd06c5205bacfe32b61261a9d29bf1fca57f91ef22cb2ba46af8cf9ae7c3123f56634099af297dcd30835cd81664005fb9140303000101", "2e4i7eenec-j2.404a4k7eenec-j2-3c264k").unwrap();
    let mut req = ScReq::new()
        .with_fingerprint(fingerprint)
        .with_alpn(ALPN::Http20)
        .with_verify(true)
        .with_timeout(timeout)
        // .with_mtls(certs, key)
        // .with_proxy(Proxy::try_from("http://127.0.0.1:10240").unwrap())
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
    let res = req.get("https://cn.bing.com", None).unwrap();
    println!("111={}", res.header());


    let mut tss = 0;
    for i in 0..100 {
        let t =Time::now_mills().unwrap();
        println!("{}", t);
        // let fingerprint = Fingerprint::from_hex_all("16030106b2010006ae0303f0aed3d4d9fac0e8d4ff98981a90257765d203b4ce089c591e86d8e7ec8ab90a204803c2150a14429bfe6536328fe11cfd4034264fa2a3a443c5972eeeb93d427100206a6a130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035010006453a3a000000230000001b0003020002ff010001000000000e000c0000093338686d7a672e636e0005000501000000000017000044cd00050003026832fe0d00ba00000100010900208e3fc249e1ce71ff4aefb0970b38167b6b7de98537b874130ba4e284e15f1c4f00909540fc3a77fcc8f96d51ff9144785ccf114d3618d9a77b0e88f54d4dd1279083483e0ad83a4f25e55951194048709bf0842651d940c291569b9cfe1323d6fc2d31348ccaaa7b79271fc41af0975d94f7a826819154e05f6f90bdaa4e2b215894ccd36f748ded2bcae0a61aa101a7187588c2b45b51d076356d0e47728974d6d1cdd2b3ce4a8e5e8f70a79fb8f288c868000b00020100002d00020101000a000c000a3a3a11ec001d00170018001200000010000e000c02683208687474702f312e31003304ef04ed3a3a00010011ec04c05b20439ba8b50e3a5800981889512ab253cd2f1ba1488613fbd79f43813c08e34ed45330a62991a6b37890d54d2d0c089251b146acace84512c031c74ac6a2ac6345b6668629aa143357b45921916de02ac5cc8d57e1ca9882ccad900640a1b51c587de3291a2f15ad67e180b79b442fe4606de978f7a27591a41ffcd91116c50703c45531999c9d377a173c249ef747a60a81158c0d3ef709b9b5a38af61b6b5c9740c343f7322b6510a60797cb39148ba310413b688354bb0b2e395dbf3935fd0a797d7b5e94acab23a95c163238dd1bc9b8b420599a0efd4726e85a0783fc8506436c3eb89ee96008b0c9c5a2047a2415bbb5a2768d7c8d58384644d5473de96721b24a3fc82ee68cc0a3a43cc73467ec515a3ac1a79b9070f4e4aad61ac50c7b4e9b125f66cba026807cdad5a43e4a5cfa2ac521801616bb58ea068689c15afd4592b26545c3a8c638800a3429c32237a902f1a605458935391c4d352a211cb2122203f9ea38e3d44b29741502bb57c7850ffaf36ab0db72ac9c0fc0ba309661096bc550d86b442beca080c0602e02a54ed2171e58b0b82582c568a5b1407d8d35448cf907a43575aed4c5371595d1456f29778c892325d4d785a3a384a30b838e6b0d59990ca54ba52369c4faf835a2f50cbd504f7d38cdc4047bf7acae92090cf121180096a513dc4cadf290641ab6e4375aa477395b8902b74c39e62b945a09438d83b1d41ac2f204c4614425bed86e221c60c8520e1c3233e5ccb53c228c0d525fb7823d9d9c4337e36785eb61590794f9565b3dd2722a2834b536be157a307d928d7f910167a314b8705bdddc1b4c9c139a5320380910b1263b40a6c6065c84266a2c036a19d3a51f5edbb8eaf3cb1e8295ef1ab978f5306da9b11a5a3df473bbd2acca084a4c4bba0bc478630283b0e6910bde3052c6f58300703a6e9524381b4cc1b247236acc1c0bae6cb69c463c29811b04d93a589ba36d30c9b4d1fb234368a9b3e94abaf419a220af730917488bc9be585f7111c9a13a8544969bf3e397b1f2ceba0ca7f21785531a3f7856248f54a5bd854124b21e1e75c366e8b5293130bdb902db0a05e9803c3d7827d5cc26046815102c3713b4a14ef63aed3163319244995a6524dbabfaf93ed8a95e08641377683dd6b3b05084bf48f77d47904d09656d4a19b457d84bcfd77a4c433393bbb43f09931cf4896cf891990c9363202467b6193ea6b8bd493733235c93c118feb808b1d9b38cc7862c744342e2baeeec6299d0a21898aa9576ae61b2703a5b072521166f6693aa4b5e6148ad4e7c21a21a7972a0c8c3f986e95392ed2b15e51a5f2e5b90e4766320513e3bfa4d67688fb6c547147c47aa71c04095336b11b32b52a6c9d047a1357eece2688efb2045184653a480ef15a3fb8c4851d8c0407b24a87b55fd36af59b18fff38b183b6256e15c161395a46f62ce1b0af240319dec84d3aa04e2773ac289b393160683e901b2b622d615b2719b06cc12bae79fca101e737a91434c8e0828cc6a71b740216964a06a9952d9c54f24743b1b9c4fc9475554aa8a87719ccd7ae40374c87d8018937c7b6007e028b348e884d201087416396ec3237b61319e0f40e436a6a1dc75f2486a68c60c27f719d251a9d73b3de3bd91858d3f3d4043384f7ad42422b47b96bdd03b5556f8107232953dad801970157aa95971638e2908d55001d0020552cb65392fdab1ff61dd3b43c895fdf782c61bb6f05519f2b7d9e28facfd25e000d0012001004030804040105030805050108060601002b000706dada030403031a1a0001001603030046100000424104ff635373fbbfbc37444a2026372f57fd06c5205bacfe32b61261a9d29bf1fca57f91ef22cb2ba46af8cf9ae7c3123f56634099af297dcd30835cd81664005fb9140303000101").unwrap();
        // let fingerprint = Fingerprint::from_ja3("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0", "4b107bbnbc-01o-3781k7bbnbc-01v25461k").unwrap();
        // let certs = Certificate::from_pem_file("/home/xl/1/client.crt").unwrap();
        // let key = RsaKey::from_pri_pem_file("/home/xl/1/client.key").unwrap();
        let mut req = ScReq::new()
            // .with_fingerprint(fingerprint)
            .with_alpn(ALPN::Http20)
            // .with_mtls(certs, key)
            .with_verify(false)
            .with_timeout(Timeout::longer())
            // .with_proxy(Proxy::new_http_plain("127.0.0.1", 10280))
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

        };
        // req.set_url("https://zhifazhe.top").unwrap();
        // req.set_url("http://3434.characlink.com").unwrap();
        // req.set_url("https://m.so.com").unwrap();
        // req.set_proxy(Proxy::new_socks5("34.124.190.108", 8080));
        // println!("{}", et - t);
        // req.set_url("https://ms.xllgl.top").unwrap();

        // req.set_url("https://jetstar.com").unwrap();
        // let et = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis();
        // println!("{}", et - t);
        // req.set_url("https://cn.bing.com/search?q=site%EF%BC%9Aqq.com&first=150&FORM=PERE2").unwrap();
        // req.set_url("https://accounts.pcid.ca/login").unwrap();
        // req.set_url("https://ccppdd.zzzzzzyyyyy.shop/api/v1/client/s9FkyFPBngt80pFn1?token=a0cedb7c6645280ec2402db62d550a17").unwrap();
        // req.set_url("https://www.link114.cn/").unwrap();
        // req.set_url("https://127.0.0.1:8000").unwrap();
        // req.set_url("http://zwfw.hubei.gov.cn/web/user/uias_login.do?appCode=hbzwfw&gotoUrl=http%3A%2F%2Fzwfw.hubei.gov.cn%2Fwebview%2Fgrkj%2Fwelcome.html&p01=").unwrap();
        req.set_auto_redirect(true);
        req.set_headers_json(headers).unwrap();
        // println!("6");
        let res = req.get("https://www.baidu.com", None).unwrap();
        let et = Time::now_mills().unwrap();
        tss += et - t;
        println!("{}", et - t);
        // res.text().unwrap();
        // println!("{}", res.header());
        // println!("{}", res.text().unwrap().len());
        // for _ in 0..50 {
        //     let resp = req.get().unwrap();
        //     // let body = res.decode_body().unwrap().as_string().unwrap();
        //     // println!("{}", resp.header().status());
        //     // println!("{}", resp.text().unwrap().len());
        //     let et = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis();
        //     println!("{}", et - t);
        // }


        // break;
    }
    println!("{}", tss / 100);
}