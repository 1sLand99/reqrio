import com.sun.jna.Pointer;
import org.xllgl2017.*;

public class Main {
    public static void main(String[] args) throws Exception {
//        WebSocket socket = new WebSocket("wss://alive.github.com");
//        socket.open();


        //初始化，可以设置版本
        Session session = new Session(ALPN.HTTP20);
        session.set_verify(false);
        session.useRandomFingerprint("w");
        //初始化头部
        Headers headers = getHeaders();
//    //设置头部
        session.setHeaders(headers);
//    //设置超时
        Timeout timeout = new Timeout();
        session.setTimeout(timeout);

        ScReqCallback cb = new ScReqCallback() {
            @Override
            public void invoke(Pointer msg, int len) {
                byte[] data = msg.getByteArray(0, len);
                System.out.println("len = " + data.length);
                return;
            }
        };

        session.set_callback(cb);
//    reqrio.setUrl("https://ticket.sxhm.com/");
        session.setUrl("https://m.so.com");
//    //请求
        Response response = session.get();
        System.out.println(response.toString());
//    Headers resp_hdr = response.getHeader();
//    Gson gson = new Gson();
//    IO.println(gson.toJson(resp_hdr));
//    HttpUtil2 util2 = new HttpUtil2();
//    IO.println("00");
//    Response response = util2.fetchIndex();
//
//    JsonObject data = new JsonObject();
//    data.add("planId", new JsonPrimitive("2010255636437147648"));
//    String token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ3ZWNoYXRfcHVibGljMSIsInVzZXJJZCI6IjE4Nzc1ODcyNjU3MDczMTUyMDAiLCJuYW1lIjoi5b6u5L-h5YWs5LyX5Y-35pWj5a6iIiwib3JnSWQiOiIxODc3MzM4MjQ2MDkyODE2Mzg0IiwiZGV2aWNlQ29kZSI6IiIsInNhbGVTdGF0aW9uSWQiOiIxODc3MzM4MjQ3NzcwNTM3OTg0IiwiY3VzdG9tZXJJZCI6IjE4Nzc1ODcyNjU4NTgzMTAxNDQiLCJzb2NpYWxDdXN0b21lcklkIjoxOTg1MjA4NjY3ODU4NzE0NjI0LCJleHAiOjE3Njg0NDA3NzN9.lFiEpgMQfCBEGssuCRAHrVD-YamH5vYose4hUEnZg72V8XhSIEHXfLL1_eZ96fkjZD_wE-JNrkeHTMJ_WAjMLZ5DRnGiKN5n0BOUyQayvUZ_SxoVryLPoJ4W19YhYAYN5yZXLpGakymtqr5q3peOR-Sy8-tLLJNolnuTNfRRMaQ";
//    String uid = "1985208667858714624";
//    JsonObject res = util2.postRuiShuOrder(response, data, token, uid);
//    IO.println(res);
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

