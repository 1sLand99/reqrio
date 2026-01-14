package org.xllgl2017;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.sun.jna.Pointer;
import org.apache.commons.codec.DecoderException;

public class Session {
    private static final ReqrioLibrary INSTANCE = ReqrioLibrary.loadLibrary();
    private final Pointer req;

    public Session(ALPN alpn) {
        this.req = INSTANCE.new_http();
        INSTANCE.set_alpn(this.req, alpn.getValue());
    }

    public Session() {
        this.req = INSTANCE.new_http();
    }

    public void setHeaderJson(String header) throws Exception {
        int res = INSTANCE.set_header_json(this.req, header);
        if (res == -1) throw new Exception("set header json error");
    }

    public void useRandomFingerprint() throws Exception {
        int res = INSTANCE.set_random_fingerprint(this.req);
        if (res == -1) throw new Exception("use random fingerprint error");
    }

    public void setHeaders(Headers headers) {
        for (Header header : headers.getKeys()) {
            INSTANCE.add_header(this.req, header.getName(), header.getValue());
        }
        for (Cookie cookie : headers.getCookies()) {
            INSTANCE.add_cookie(this.req, cookie.getName(), cookie.getValue());
        }
    }

    public void addHeader(Header header) throws Exception {
        int res = INSTANCE.add_header(this.req, header.getName(), header.getValue());
        if (res == -1) throw new Exception("add header error");
    }

    public void addHeader(String name, String value) throws Exception {
        int res = INSTANCE.add_header(this.req, name, value);
        if (res == -1) throw new Exception("add header error");
    }

    public void setALPN(ALPN alpn) throws Exception {
        int res = INSTANCE.set_alpn(this.req, alpn.getValue());
        if (res == -1) throw new Exception("set alpn error");
    }

    public void set_fingerprint(String fingerprint) throws Exception {
        int res = INSTANCE.set_fingerprint(this.req, fingerprint);
        if (res == -1) throw new Exception("set fingerprint error");
    }

    public void setJa3(String ja3) throws Exception {
        int res = INSTANCE.set_ja3(this.req, ja3);
        if (res == -1) throw new Exception("set ja3 error");
    }

    public void setJa4(String ja4) throws Exception {
        int res = INSTANCE.set_ja4(this.req, ja4);
        if (res == -1) throw new Exception("set ja4 error");
    }

    public void setProxy(String proxy) throws Exception {
        int res = INSTANCE.set_proxy(this.req, proxy);
        if (res == -1) throw new Exception("set alpn error");
    }

    public void setUrl(String url) throws Exception {
        int res = INSTANCE.set_url(this.req, url);
        if (res == -1) throw new Exception("set url error");
    }

    public void addParam(String name, String value) throws Exception {
        int res = INSTANCE.add_param(this.req, name, value);
        if (res == -1) throw new Exception("add param error");
    }

    public void setData(JsonObject data) throws Exception {
        int res = INSTANCE.set_data(this.req, new Gson().toJson(data));
        if (res == -1) throw new Exception("set data error");
    }

    public void setJson(JsonElement json) throws Exception {
        int res = INSTANCE.set_json(this.req, new Gson().toJson(json));
        if (res == -1) throw new Exception("set json error");
    }

    public void setBytes(byte[] bytes) throws Exception {
        int res = INSTANCE.set_bytes(this.req, bytes, bytes.length);
        if (res == -1) throw new Exception("set bytes error");
    }

    public void setText(String text) throws Exception {
        int res = INSTANCE.set_text(this.req, text);
        if (res == -1) throw new Exception("set content_type error");
    }

    public void setTimeout(Timeout timeout) throws Exception {
        Gson gson = new Gson();
        int res = INSTANCE.set_timeout(this.req, gson.toJson(timeout));
        if (res == -1) throw new Exception("set timeout error");
    }

    public void setCookie(String cookie) throws Exception {
        int res = INSTANCE.set_cookie(this.req, cookie);
        if (res == -1) throw new Exception("set cookie error");
    }

    public void addCookie(String name, String value) throws Exception {
        int res = INSTANCE.add_cookie(this.req, name, value);
        if (res == -1) throw new Exception("add cookie error");
    }


    public Response send(Method method) throws DecoderException {
        Pointer ptr;
        switch (method) {
            case GET:
                ptr = INSTANCE.get(this.req);
                break;
            case POST:
                ptr = INSTANCE.post(this.req);
                break;
            case PUT:
                ptr = INSTANCE.put(this.req);
                break;
            case OPTIONS:
                ptr = INSTANCE.options(this.req);
                break;
            case DELETE:
                ptr = INSTANCE.delete(this.req);
                break;
            case HEAD:
                ptr = INSTANCE.head(this.req);
                break;
            case TRACH:
                ptr = INSTANCE.trach(this.req);
                break;
            default:
                throw new IllegalArgumentException("Unsupported method: " + method);
        }
        String hex_res = ptr.getString(0);
        Response response = new Response(hex_res);
        INSTANCE.free_pointer(ptr);
        return response;
    }

    public Response get() throws Exception {
        return this.send(Method.GET);
    }

    public Response post() throws Exception {
        return this.send(Method.POST);
    }

    public Response put() throws Exception {
        return this.send(Method.PUT);
    }

    public Response options() throws Exception {
        return this.send(Method.OPTIONS);
    }

    public Response head() throws Exception {
        return this.send(Method.HEAD);
    }

    public Response delete() throws Exception {
        return this.send(Method.DELETE);
    }

    public Response trach() throws Exception {
        return this.send(Method.TRACH);
    }

    public void close() {
        INSTANCE.destroy(this.req);
    }


}
