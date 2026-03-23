import org.xllgl2017.*;

public class Main {
    public static void main(String[] args) throws Exception {
        //初始化，可以设置版本
        Session session = new Session(ALPN.HTTP20);
        session.setVerify(false);
        session.useRandomFingerprint("w");
        //初始化头部
        Headers headers = getHeaders();
        //设置头部
        session.setHeaders(headers);
        //设置超时
        Timeout timeout = new Timeout();
        session.setTimeout(timeout);

        session.set_callback((msg, len) -> {
            byte[] data = msg.getByteArray(0, len);
            System.out.println("len = " + data.length);
        });
        session.setUrl("https://m.so.com");
        session.setText("sdfdfdgdfgdfgdfgsf");
        //请求
        Response response = session.get();
        System.out.println(response.toString());
        //关闭资源，或使用try-with-resources
        session.close();
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

