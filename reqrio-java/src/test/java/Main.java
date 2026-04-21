import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import org.xllgl2017.*;

public class Main {
    public static void main(String[] args) throws Exception {
//        Session session = new Session(ALPN.HTTP20);
//        session.addHeader("Host", "h5.moutai519.com.cn");
//        session.addHeader("Accept", "application/json, text/javascript, */*; q=0.01");
//        session.addHeader("x-csrf-token", "");
//        session.addHeader("X-Requested-With", "XMLHttpRequest");
//        session.addHeader("MT-APP-Version", "1.9.6");
//        session.addHeader("User-Agent", "Mozilla/5.0 (Linux; Android 12; 2201123C Build/SKQ1.211006.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/95.0.4638.74 Mobile Safari/537.36 moutaiapp/1.9.6 device-id/6d7ea798f3de56bf27055cd8bc670637 BS-DVID/dYjWelUeUAvFmD_qgi61OLEOvNhpC-FrRdaoKXmKaeuqW46DupmeMxDw1mEW3W1ZoQWUSHPii5Hwfn__66pBB3A");
//        session.addHeader("content-type", "application/json");
//        session.addHeader("Origin", "https://h5.moutai519.com.cn");
//        session.addHeader("Sec-Fetch-Site", "same-origin");
//        session.addHeader("Sec-Fetch-Mode", "cors");
//        session.addHeader("Sec-Fetch-Dest", "empty");
//        session.addHeader("Referer", "https://h5.moutai519.com.cn/mt/item/smsp-detail?appConfig=2_1_2");
//        session.addHeader("Accept-Language", "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7");
//        session.addHeader("Cookie", "MT-Token-Wap=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJtdCIsImV4cCI6MTc3OTA2ODE5MSwidXNlcklkIjoxMTMxODU1ODI4LCJkZXZpY2VJZCI6ImNsaXBzX2V4OHFTWDlNS1JCeVFDVkJkaGNpRW5RV0pSQWtSaWRFSlJJblEzRkdmeG89IiwiaWF0IjoxNzc2NDc2MTkxfQ.KqT_ZlEWu6hd0rJv4zg8B8-ekvOhvPJe79KQmS9PzMI; MT-Device-ID-Wap=clips_ex8qSX9MKRByQCVBdhciEnQWJRAkRidEJRInQ3FGfxo=; _sdk_v_=V3.5.0_20260403.1_imaotai; _bs_device_id=bid-3841126746771-dba9-9627; YX_SUPPORT_WEBP=1; _d_u=e4d5c88b10a02b561da7917769e4029690f571afa79ca84494106fc65c27aca5e8dc4328f4bf303a8e6c976c987f55421243a12d500adcad5191ec74fc24e0a4c0a0f088dbd3397a19aec5ed436f130550b464227bdc9046eddffb8925df65e359e574c582d7354681129af1071a910a8b16d0972eaa137206678aaed913c65622575d5f3263d10552cc68a7d35c6297b498ce1f8fee0034c8e8cf65439c81c224f038cba7299392e6631596c88d5550e60de6f39112417e69b5dc1bf2e0e1d5bf1671071102f1197814284a0fcc864f09367f227f986decd9ebdec677d13e828a3dac7875502e78156b7d1f1d858f5ca07da56030266c8970fe92a5c081922b");
//        JsonObject data = new JsonObject();
//        data.add("hot", new JsonPrimitive(true));
//        data.add("spuId", new JsonPrimitive("IMTP1000313"));
//        data.add("jt", new JsonPrimitive("anonymous"));
//        session.setUrl("https://h5.moutai519.com.cn/xhr/front/mall/item/purchaseInfoV2");
//        session.setJson(data);
//        Response resp = session.post();
//        System.out.println(resp.getHeader().getStatus());
//        System.out.println(resp.toJson());
//        session.close();
        Session session = new Session(ALPN.HTTP20);
        session.useRandomFingerprint("2f-o7ffnfc-j2f7q7n-k7ffnfc-m423p26-k");
        session.addHeader("Host", "h5.moutai519.com.cn");
        session.addHeader("MT-V", "e51dc8d2ea17c389f075b250944");
        session.addHeader("MT-Device-ID", "clips_ex8qSX9MKRByQCVBdhciEnQWJRAkRidEJRInQ3FGfxo=");
        session.addHeader("Content-Web-Bb", "43a10f6dcb29587e8543a10f6dcb29871e0a30ab5ab28e992d14d4ad4bc56e9d800f39dd6a0a4fbe2f4e2eb52e4a5e8506a108062e72d8b4b9e74682b5821beb899e1854f88b26a7baac671f134144042f11df61615e3604c4f7c78be0a47c35db1f082cef1c009555340eab3a58d9f3c2e1923b8435122b00b9615c8e5d127a8da9009f914b6a0593b11b7f2ef59cfb3951fe624c61a484921b0333010c579ce64f19bbffcd67d94630a3c23f46e1330f03a7e8a1a7801f47c10d924403e00a70cff3501e8820b2c0495e7e617b17a703a72fdb88a35891eebee8e260e340d83429d4728ed718f13ced75351c94448f1ad3937353d45c4cec15888c7e1dd5dd467881852ae4e331afc5e415e36bac6e61f2d9488f8247db2c7d8857b3354f7747b1e1a406aa86c6b100edef50a7e2e43e18920cc0681ad5acea5ce8dc40ad87264bb4962aa4f29ca8db0d7ce50e4bc83cef5d0edfbc2fd8f57f41b80d607e61ec06c57cb0ff3b2d5ebd33d9fab3b022526c0de974c0ff04b2ea1d0f3c1385e2");
        session.addHeader("x-csrf-token", "");
        session.addHeader("MT-APP-Version", "1.9.6");
        session.addHeader("Sdk-Ver-Bb", "V3.5.0_20260403.1_imaotai");
        session.addHeader("content-type", "application/json");
        session.addHeader("Accept", "application/json, text/javascript, */*; q=0.01");
        session.addHeader("Content-Hh-Bb", "4ffa3f38f6ea5e2e481792a4c7e895dc");
        session.addHeader("X-Requested-With", "XMLHttpRequest");
        session.addHeader("MT-Info", "a3f9c2b8471de05f9b6c4e1287d5a9c1");
        session.addHeader("User-Agent", "Mozilla/5.0 (Linux; Android 12; 2201123C Build/SKQ1.211006.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/95.0.4638.74 Mobile Safari/537.36 moutaiapp/1.9.6 device-id/6d7ea798f3de56bf27055cd8bc670637 BS-DVID/dYjWelUeUAvFmD_qgi61OLEOvNhpC-FrRdaoKXmKaeuqW46DupmeMxDw1mEW3W1ZoQWUSHPii5Hwfn__66pBB3A");
        session.addHeader("MT-K", String.valueOf(System.currentTimeMillis()));
        session.addHeader("Origin", "https://h5.moutai519.com.cn");
        session.addHeader("Sec-Fetch-Site", "same-origin");
        session.addHeader("Sec-Fetch-Mode", "cors");
        session.addHeader("Sec-Fetch-Dest", "empty");
        session.addHeader("Referer", "https://h5.moutai519.com.cn/mt/item/smsp-detail?appConfig=2_1_2");
        session.addHeader("Accept-Language", "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7");
        session.addHeader("Cookie", "MT-Token-Wap=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJtdCIsImV4cCI6MTc3OTA2ODE5MSwidXNlcklkIjoxMTMxODU1ODI4LCJkZXZpY2VJZCI6ImNsaXBzX2V4OHFTWDlNS1JCeVFDVkJkaGNpRW5RV0pSQWtSaWRFSlJJblEzRkdmeG89IiwiaWF0IjoxNzc2NDc2MTkxfQ.KqT_ZlEWu6hd0rJv4zg8B8-ekvOhvPJe79KQmS9PzMI; MT-Device-ID-Wap=clips_ex8qSX9MKRByQCVBdhciEnQWJRAkRidEJRInQ3FGfxo=; _sdk_v_=V3.5.0_20260403.1_imaotai; _bs_device_id=bid-3841126746771-dba9-9627; YX_SUPPORT_WEBP=1; _d_u=e4d5c88b10a02b561da7917769e4029690f571afa79ca84494106fc65c27aca5e8dc4328f4bf303a8e6c976c987f55421243a12d500adcad5191ec74fc24e0a4c0a0f088dbd3397a19aec5ed436f1305b6a5864341c6583e0ee4f209c797e4c3816322a8be5ec5307ed3a93655157a8602b373e53c179d57847496d5356203334d04ae24573ce510c7bfc936bb10c96ba7b34f6274fb0fc7744fd11ae49be4594ec542433ae05d362fbe81d3afa744bc103e23f38cabfce062eec91c6e0be1bf7c8fed555d313f58c66d67ee08c110ccfa6065470dd3115c14d128b2a2b236ec9998f6deb5a9598815cde33cb0092d59b4bc59dc4d035d40bd72987977ac092e");
        Timeout timeout = new Timeout();
        //建立tcp超时时间
        timeout.setConnect(3000);
        //每次tcp读取超时时间
        timeout.setRead(2000);
        //每次写出tcp超时时间
        timeout.setWrite(2000);
        //处理整个请求超时时间
        timeout.setHandle(4000);
        //尝试连接的次数，连接失败，且失败次数小于时将重试
        timeout.setConnect_times(1);
        //尝请求接的次数，请求失败，且失败次数小于时将重试
        timeout.setHandle_times(100);
        session.setTimeout(timeout);


        session.setProxy("http://127.0.0.1:10280");
        String url = "https://h5.moutai519.com.cn/xhr/front/trade/priority/rushPurchase/hot/branch/one";
        JsonObject data = new JsonObject();
        data.add("actParam", new JsonPrimitive("SSeGBjTN7FYJHdAJdtdL3u4vjeXv7Y37r+avAPs/6T1cEL9+dmFRnCKwWg8C9o+JPwApiYVugWVgXydUgQxQEvEnDfHtdslU6Ov8d7NTYyvr2blYmpdg4Bmi0wLTQPUiEjDlMWr2XhQCeYLP45vUlWPyOHiQm5h8AoO8/mRSt5YK8303PmchPb60L2BIN8bNc5sM73JAbsRDefuPTAhCJ/lSTk3oQFEPLF/QDex+w01tks1q5j7R69S3kELhajmWtDCrYekK0FMO9kzrHtRk/iawGmzLgw4qXGp7zMvH/MgFarOPBF8mBhMc4Rzn6SgScdcpuuspyw7DgKrp6KXIUtxE2hIiCT84yolMyEhbrUpu85UFDddDl8yCkbJ/b+FLy095fGJbqdjpq65yYtq+v6mDHTxffgc7D6LvrDdcN7Y="));

        session.setJson(data);
        session.setUrl(url);
        session.setJson(data);
        Response resp = session.post();


        System.out.println(resp.getHeader().getStatus());
        System.out.println(resp.toString());
        //        //初始化，可以设置版本，有指纹检测优先使用HTTP/2.0
//        Session session = new Session(ALPN.HTTP20);
//        session.setVerify(false);
//
//        //=======================>指纹设置(四选一)<==============================
////        //使用随机tls指纹
////        session.useRandomFingerprint("0");
////        //使用ja3设置指纹
////        session.setJa3("771,4866-4867-4865-49196-49200-49195-49199-52393-52392-49188-49192-49187-49191-159-158-107-103-255,0-11-10-16-22-23-49-13-43-45-51-21,29-23-30-25-24-256-257-258-259-260,0-1-2", "");
////        //使用ja4设置指纹
////        session.setJa4("t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01_0403,0804,0401,0503,0805,0501,0806,0601", "");
////        //使用tls1.2完整握手数据设置指纹
////        session.set_fingerprint("160301072401000720030347c8885be57c7b5ef724505f486efff05173d7ac332ff5764b7509f845f2f4cd20ea5e1d057803dd84d88a0e0d0ba7578e38bfb307cd60808f710d100c13bda4110020dada130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035010006b71a1a0000002d00020101000b00020100000500050100000000003304ef04edfafa00010011ec04c0c399b44b802ea789831e2625ebd68a136b713e80a50233a22dbc8002a6aab07ba3afd935e2f315ddb72dfa4a94f75a7494da759b03780f558a3d0a0608a38d8af2122d1ccca3a9121b5387e9da46d913b539b0c9d6b4a68a9a15f825892b26ce70815b159a7dee77ab7ea5b4fd30b9f202818ba6c7551a65f011654307b334716e667651c4e7a2a5e14ff43b271fe627273246268628157b641a62751e30b263657f160868d8d7b8095439d97941759874943c6a12da92b7d146e4e870a4e90541a23b7c5ab1c6448f7188563a097c5f78a349073737d7a37cdb08bcb09ca6dc31b4229260d88a93c7a948411e7da3b309c41987771bf8c71151aa9bc4369f1515463587c42387bb48c52846491b1d9227c0686fa1549246f44424aa258e443b431096ec2ccd377a88e24c98229236fa016bab815466c40eeae134ca77704348a2b6627cbed551d1ea0daf635206d425f600c73edc4b98c02bdf0b5efc7b73ce75a2924043e2436c944771630259f0516b30b529a64062b3098dc8343852e598887c88dbaa0b2c709b1a58941916ba4edb9caec90eb6f930f9da5cb58bb855862b59263eeda31d2a06a89763b838d10f6a0c3199c1b10bcc9d1549b0e860a1f0901698c350b7eb5e86104ff631361fd6beec2c77806362833c2efa3063810c86faa7b5ab92389eab258320265fb23f0d7a2b3a9aad03c94604cb43d532376314b2e8d4cfedda36b578b590e6146ea18c6847a0569c8318a68620f294e9d9875d014549695bd3ca68c430577092a375ac3a37203a0336c1e134b45af2548bccc8ce075e4e74a370f16d4bcbc90c8cb42ed09b5dd05c620528d9dac66833bc02e7734967c6a7cc4bebe95b85d7275b976c9ac0997eb264a0a684d4279512054a3258a39e604f1ec148ca2130d29a1ab92b53c1b0ab4ee3805f339201e968847b78739175fd695181b7a7ce500bd31a0685926e04d5ce6d2b612845ba68d39f617c21afa75f26bca95c17507698af280c0c5f21890ab78a8e56b1e94509b226066624a7c6701c3ae461c54161e7d5760279acc167cc01908b7d4a19576459e9b6276ce2c791990851fb9f8b197cf0c96de1fb61cd1c13c222c5194182edc4695e295d54a506fa09b0881169a6f32a8afc0acd5644876b5e698105f36a56a16aaf49041ea34a92619969b983025d585ee6f1bcfa131e995431b2b3a68b514534a599af1c13ad095d38cb458a1a8ac7f51524503166a63cf6d8963aa89a20c37013984672f79a9be13f93719d89e765a82a4775d531b3ebcb8b4c2935510ba6a770bc10a8a4ec60f01a9a20250050d96c535454f5b69b8cf8c00c44790f3964a1f4b2fabc5a85f061348c89e3ba1797c0c26bf3bbcad70d93822f932a18ca7ca0cf866c6b1b4de2571606f01eb2e5ab3be719c91370f29363a218aacf40284dc6c3c59671df4b62d5e44e81039c3498248a7659f0074996533e8097a0aee389a6d9ae9364b3a64bcf4e576f67802b89943ae03a24d2772726887f5fc803933111d4aa35da30a78b560bb4ec2dc918a3998281f046093f897919078ebdf05ec7f7ce03311a79bc49cb537322e8c6a6abbe56a55f6e1555e384ba6fa9c4f8e0189d3650c26aee67cbe704d7465022c259b6534361651c9b6d71fc98e18f84ff8aa1f3e880bcdbd8eddd440e3d7e99580bd9bc7f83f444daa761442c1a625dc5d44da361001d0020afa0c21e9ab34f115732ecb8e6b5d83379c4660811738d8be560cafde446fd0b00000020001e00001b6d63732d6d696d702d7765622e73662d657870726573732e636f6d002b0007064a4a03030303000a000c000afafa11ec001d0017001800230000001b000302000244690005000302683100170000fe0d011a0000010001960020cb3de92f31efcfcd5a53c79fbe3200c1f481e37199aa290649f1abad6ed5031e00f0dcb724c041356d77ecf7cf213696ee291b549ee48b028251d6ddde9865586ea997acd0a5210799395fd9682738cf609dd99a9c829efbc5ba83ffc2d8932b551886b5c1ebc1ac1233273e5ccfe8fa1e50fb0812f05f0fcb607672a934c778acc998173d746e8672f2aa6b60efa66369ffd7c03b9d7dcf3fc3f0cdb255347d8394dae22615b14c5ff626fa8e65b5d93278da980f307f21af1a124cab78db6d41d1cfe69d7f1ab90038f7d209f85e7d7d5ad045a2ca484569320dcae3f33b163992f0e68268899d3dabdb83f3177f115f97d165ba545ef9c193a16abc8ad3b24d458af544fb553218136e8dfa1230aa000c0010000e000c02683108687474702f312e3100120000000d0012001004030804040105030805050108060601ff01000100eaea00010016030300251000002120db295d27307243c8688dc4c8136ad6241713f787a2a6554d616e27965b789a41140303000101", "");
//
//
//        //初始化头部
//        Headers headers = getHeaders();
//        //设置头部
//        session.setHeaders(headers);
//        //设置超时
//        Timeout timeout = new Timeout();
//        session.setTimeout(timeout);
//        example_post(session);
//        return;
//
//////        session.set_callback((msg, len) -> {
//////            byte[] data = msg.getByteArray(0, len);
//////            System.out.println("len = " + data.length);
//////        });
////        //设置代理，需要在setUrl之前
//////        session.setProxy("http://127.0.0.1:10280");
//////        session.setProxy("socks5://127.0.0.1:10279");
////        //认证模式
//////        session.setProxy("socks5://username:password@127.0.0.1:10279");
////
//////        session.setUrl("https://github.com");
////        //==========================>设置请求体<=======================================
////        //设置·文本·请求体
//////        session.setText("sdfdfdgdfgdfgdfgsf");
////        //设置·表单·请求体
////        JsonObject form = new JsonObject();
////        //这里不需要做url编码，底层自动做了
////        form.add("key1", new JsonPrimitive("value1"));
////        form.add("key2", new JsonPrimitive("value2"));
////        session.setData(form);
////        //请求
////        Response response = session.get();
////        System.out.println(response.toString());
////        //关闭资源，或使用try-with-resources
////        session.close();
    }

    private static void example_post(Session session) throws Exception {
        session.setUrl("https://api.github.com");
        JsonObject data = new JsonObject();
        data.add("key1", new JsonPrimitive("value1"));
        data.add("key2", new JsonPrimitive("value2"));
        session.setJson(data);
        Response resp = session.post();
        System.out.println(resp);

        session.setUrl("https://api.github.com");
        JsonObject text = new JsonObject();
        text.add("key1", new JsonPrimitive("value1"));
        text.add("key2", new JsonPrimitive("value2"));
        System.out.println(text);
        session.setText(text.toString());
        session.setContextType("application/json");
        Response resp1 = session.post();
        System.out.println(resp1);
    }


    private static Headers getHeaders() {
        Headers headers = new Headers();
        headers.addHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7");
        headers.addHeader("Accept-Encoding", "gzip, deflate, br, zstd");
        headers.addHeader("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6");
        headers.addHeader("Cache-Control", "no-cache");
        headers.addHeader("Connection", "keep-alive");
        headers.addHeader("Host", "m.so.com");
        headers.addHeader("Pragma", "no-cache");
        headers.addHeader("Sec-Fetch-Dest", "document");
        headers.addHeader("Sec-Fetch-Mode", "navigate");
        headers.addHeader("Sec-Fetch-Site", "none");
        headers.addHeader("Sec-Fetch-User", "?1");
        headers.addHeader("Upgrade-Insecure-Requests", "1");
        headers.addHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0");
        headers.addHeader("sec-ch-ua", "\"Microsoft Edge\";v=\"143\", \"Chromium\";v=\"143\", \"Not A(Brand\";v=\"24\"");
        headers.addHeader("sec-ch-ua-mobile", "?0");
        headers.addHeader("sec-ch-ua-platform", "\"Windows\"");
        //添加cookie，也可以用reqrio.setCookie
        headers.setCookies("__guid=15015764.1071255116101212729.1764940193317.2156; env_webp=1; _S=pvc5q7leemba50e4kn4qis4b95; QiHooGUID=4C8051464B2D97668E3B21198B9CA207.1766289287750; count=1; so-like-red=2; webp=1; so_huid=114r0SZFiQcJKtA38GZgwZg%2Fdit1cjUGuRcsIL2jTn4%2FE%3D; __huid=114r0SZFiQcJKtA38GZgwZg%2Fdit1cjUGuRcsIL2jTn4%2FE%3D; gtHuid=1");
        return headers;
    }
}

