import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import com.google.gson.reflect.TypeToken;
import org.jetbrains.annotations.NotNull;
import org.xllgl2017.*;

import java.io.FileReader;
import java.lang.reflect.Type;
import java.util.Base64;
import java.util.List;

class Fingerprint {
    String sec_ch_ua;
    String sec_ch_ua_mobile;
    String sec_ch_ua_platform;
    String tls_finger;
    String user_agent;
}


public class HttpUtil2 {
    private final List<Fingerprint> fingerprints;

    private final Session session;

    HttpUtil2() throws Exception {
        Gson gson = new Gson();
        FileReader reader = new FileReader("nls_100.json");
        Type type = new TypeToken<List<Fingerprint>>() {
        }.getType();
        this.fingerprints = gson.fromJson(reader, type);
        Headers headers = getHeaders();
        //初始化session
        this.session = new Session(ALPN.HTTP20);
        //添加tls指纹
        this.session.set_fingerprint("160301022c0100022803033eb19aa88a78e938aef40321e839e6fff7384fd064a6e7cea33275f5e3f9e17620b119c85aa135227cac32c5615660febf6146572f159f78ee256c076d02574b2800200a0a130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035010001bfcaca0000fe0d00fa00000100015e00203fa82978b229c736bed3c61c45aa03de26575a474dc5d9254c8ef5c44e7c294a00d024390be7abbba7a8987f0e6474467a1f74e37ef97bc89b4e4e8fef200bb1474c97039a8abe9a0dc20f4f165535722d4a351cf16bbe744a8f9b7945c4f315230fe2a8773505fe1c2b31d398970376e60af45e60ab4f0ac9371529a7b365fd0874cdc8c8e660b9a4a267f2c414de877bad775a9cd1a87d1cdd25e86d67bd53b1d1c5f656b8e604647e32762155d09396f2a29db4fee4b485c1066070d2b47b4eba38bfe5a6b46e9f6f04ac107997ac59e9795c31fc250fa62d6d533e09c4708c5002179ee12f891d5736c3368352bf8dfe44cd00050003026832ff0100010000230000001b0003020002000a000a0008aaaa001d00170018001200000010000e000c02683208687474702f312e31000500050100000000002b0007062a2a030403030000000e000c0000093338686d7a672e636e002d00020101000b000201000033002b0029aaaa000100001d00207f77d6622a5a380dcdc7367ff60cde95db902784e029e6cbc6adc39a6bf7d533000d0012001004030804040105030805050108060601001700008a8a0001001603030046100000424104ff635373fbbfbc37444a2026372f57fd06c5205bacfe32b61261a9d29bf1fca57f91ef22cb2ba46af8cf9ae7c3123f56634099af297dcd30835cd81664005fb9140303000101");
        //设置请求头
        this.session.setHeaders(headers);
        //设置代理
//        session.setProxy("http://127.0.0.1:10280");
        //设置url并建立建立
        this.session.setUrl("https://ticket.sxhm.com/quickticket/index.html");
    }

    private static @NotNull Headers getHeaders() {
        Headers headers = new Headers();
        headers.addHeader("Accept", "*/*");
        headers.addHeader("Accept-Language", "zh-CN,zh;q=0.9");
        headers.addHeader("Cache-Control", "no-cache");
        headers.addHeader("Referer", "https://ticket.sxhm.com/quickticket/index.html");
        //添加浏览器相关指纹数据,ua必须使用微信ua
        headers.addHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 NetType/WIFI MicroMessenger/7.0.20.1781(0x6700143B) WindowsWechat(0x63090a13) UnifiedPCWindowsWechat(0xf254140c) XWEB/16925 Flue");
        return headers;
    }

    Response fetchIndex() throws Exception {
        Response resp_index = this.session.get();
        IO.println("kkk");
        JsonObject data = new JsonObject();
        data.add("html", new JsonPrimitive(Base64.getEncoder().encodeToString(resp_index.toString().getBytes())));
        data.add("apiUrl", new JsonPrimitive("https://ticket.sxhm.com/quickticket/index.html"));
        Session ses = new Session();
        ses.setUrl("http://124.220.66.8:8082/cookies");
        ses.setJson(data);
        Response ses_index = ses.post();
        IO.println("kkllk");
        JsonObject cookies = ses_index.toJson().getAsJsonObject().getAsJsonObject("cookies");
        //记得关闭资源
        ses.close();
        //第一次更新cookie
        for (String key : cookies.keySet()) {
            this.session.addCookie(key, cookies.get(key).getAsString());
        }
        return this.session.get();

    }


    public JsonObject postRuiShuOrder(Response resp_index, JsonElement json, String token, String uid) throws Exception {
        JsonObject obj = new JsonObject();
        obj.add("html", new JsonPrimitive(Base64.getEncoder().encodeToString(resp_index.toString().getBytes())));
        obj.add("apiUrl", new JsonPrimitive("https://ticket.sxhm.com/applet/bms/sale_order/orderReservation"));
        Session ses = new Session();
        ses.setUrl("http://124.220.66.8:8082/cookies");
        ses.setJson(obj);
        Response ses_index = ses.post();
        ses.close();
        JsonObject data = ses_index.toJson().getAsJsonObject();
        for (String key : data.getAsJsonObject("cookies").keySet()) {
            this.session.addCookie(key, data.getAsJsonObject("cookies").get(key).getAsString());
        }
        String url = data.get("rsurl").getAsString();
        this.session.addHeader(new Header("uid", uid));
        this.session.addHeader(new Header("token", token));
        //url的设置需要在body设置前面
        this.session.setUrl(url);
        //设置body类型
        this.session.setJson(json);
        Response response = this.session.post();
        return response.toJson().getAsJsonObject();
    }

}

