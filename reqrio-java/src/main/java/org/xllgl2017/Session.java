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
        this.req = INSTANCE.ScReq_new();
        INSTANCE.ScReq_set_alpn(this.req, alpn.getValue());
    }

    public Session() {
        this.req = INSTANCE.ScReq_new();
    }

    public void setVerify(boolean verify) {
        INSTANCE.ScReq_set_verify(this.req, verify);
    }

    public void setHeaderJson(String header) throws Exception {
        int res = INSTANCE.ScReq_set_header_json(this.req, header);
        if (res == -1) throw new Exception("set header json error");
    }

    public void useRandomFingerprint(String token) throws Exception {
        int res = INSTANCE.ScReq_set_random_fingerprint(this.req, token);
        if (res == -1) throw new Exception("use random fingerprint error");
    }

    public void setHeaders(Headers headers) {
        for (Header header : headers.getKeys()) {
            INSTANCE.ScReq_add_header(this.req, header.getName(), header.getValue());
        }
        for (Cookie cookie : headers.getCookies()) {
            INSTANCE.ScReq_add_cookie(this.req, cookie.getName(), cookie.getValue());
        }
    }

    public void addHeader(Header header) throws Exception {
        int res = INSTANCE.ScReq_add_header(this.req, header.getName(), header.getValue());
        if (res == -1) throw new Exception("add header error");
    }

    public void addHeader(String name, String value) throws Exception {
        int res = INSTANCE.ScReq_add_header(this.req, name, value);
        if (res == -1) throw new Exception("add header error");
    }

    public void setALPN(ALPN alpn) throws Exception {
        int res = INSTANCE.ScReq_set_alpn(this.req, alpn.getValue());
        if (res == -1) throw new Exception("set alpn error");
    }

    public void set_fingerprint(String fingerprint, String token) throws Exception {
        int res = INSTANCE.ScReq_set_fingerprint(this.req, fingerprint, token);
        if (res == -1) throw new Exception("set fingerprint error");
    }

    public void setJa3(String ja3, String token) throws Exception {
        int res = INSTANCE.ScReq_set_ja3(this.req, ja3, token);
        if (res == -1) throw new Exception("set ja3 error");
    }

    public void setJa4(String ja4, String token) throws Exception {
        int res = INSTANCE.ScReq_set_ja4(this.req, ja4, token);
        if (res == -1) throw new Exception("set ja4 error");
    }

    public void setProxy(String proxy) throws Exception {
        int res = INSTANCE.ScReq_set_proxy(this.req, proxy);
        if (res == -1) throw new Exception("set alpn error");
    }

    public void setUrl(String url) throws Exception {
        int res = INSTANCE.ScReq_set_url(this.req, url);
        if (res == -1) throw new Exception("set url error");
    }

    public void addParam(String name, String value) throws Exception {
        int res = INSTANCE.ScReq_add_param(this.req, name, value);
        if (res == -1) throw new Exception("add param error");
    }

    public void setData(JsonObject data) throws Exception {
        int res = INSTANCE.ScReq_set_data(this.req, new Gson().toJson(data));
        if (res == -1) throw new Exception("set data error");
    }

    public void setJson(JsonElement json) throws Exception {
        int res = INSTANCE.ScReq_set_json(this.req, new Gson().toJson(json));
        if (res == -1) throw new Exception("set json error");
    }

    public void setBytes(byte[] bytes) throws Exception {
        int res = INSTANCE.ScReq_set_bytes(this.req, bytes, bytes.length);
        if (res == -1) throw new Exception("set bytes error");
    }

    public void setText(String text) throws Exception {
        int res = INSTANCE.ScReq_set_text(this.req, text);
        if (res == -1) throw new Exception("set content_type error");
    }

    public void setTimeout(Timeout timeout) throws Exception {
        Gson gson = new Gson();
        int res = INSTANCE.ScReq_set_timeout(this.req, gson.toJson(timeout));
        if (res == -1) throw new Exception("set timeout error");
    }

    public void setCookie(String cookie) throws Exception {
        int res = INSTANCE.ScReq_set_cookie(this.req, cookie);
        if (res == -1) throw new Exception("set cookie error");
    }

    public void addCookie(String name, String value) throws Exception {
        int res = INSTANCE.ScReq_add_cookie(this.req, name, value);
        if (res == -1) throw new Exception("add cookie error");
    }

    public void reconnect() throws Exception {
        int ret = INSTANCE.ScReq_reconnect(this.req);
        if (ret == -1) throw new Exception("reconnect error");
    }

    public void set_callback(ScReqCallback cb) throws Exception {
        int ret = INSTANCE.ScReq_set_callback(this.req, cb);
        if (ret == -1) throw new Exception("set callback error");
    }


    public Response send(Method method) throws DecoderException {
        Pointer ptr = INSTANCE.ScReq_stream_io(this.req, method.getValue());
        String hex_res = ptr.getString(0);
        Response response = new Response(hex_res);
        INSTANCE.char_free(ptr);
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

    public Response trace() throws Exception {
        return this.send(Method.TRACE);
    }

    public Response patch() throws Exception {
        return this.send(Method.PATCH);
    }

    public void close() {
        INSTANCE.ScReq_drop(this.req);
    }


}
