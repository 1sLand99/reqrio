package org.xllgl2017;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;

import java.io.StringWriter;
import java.util.HashMap;

public class Body implements AutoCloseable {
    Pointer raw;

    public Body() {
        this.raw = Session.INSTANCE.Body_none();
    }

    /// @param body        :请求体二进制
    /// @param contentType : 请求头类型
    public Body(byte[] body, String contentType) throws Exception {
        PointerByReference err = new PointerByReference();
        this.raw = Session.INSTANCE.Body_new(body, body.length, contentType, err);
        util.check_err_pointer(err);
    }

    /// @param json :json请求头
    public Body(JsonElement json) throws Exception {
        this(json.toString().getBytes(), "application/json");
    }

    public Body(HashMap<String, String> forms) throws Exception {
        StringWriter writer = new StringWriter();
        for (String key : forms.keySet()) {
            writer.write(key);
            writer.write("=");
            Pointer ptr = Session.INSTANCE.url_encode(forms.get(key));
            if (ptr == null) throw new Exception("value encode error");
            writer.write(ptr.getString(0));
            Session.INSTANCE.char_free(ptr);
            writer.write("&");
        }
        String encoded = writer.toString();
        if (encoded.endsWith("&")) {
            encoded = encoded.substring(0, encoded.length() - 1);
        }
        byte[] form_bytes = encoded.getBytes();
        PointerByReference err = new PointerByReference();
        this.raw = Session.INSTANCE.Body_new(form_bytes, form_bytes.length, "application/x-www-form-urlencoded", err);
        util.check_err_pointer(err);

    }

    /// @param text         :请求体文本
    public Body(String text) throws Exception {
        this(text.getBytes(), "text/plain");
    }

    public Body(HttpFile file) throws Exception {
        this(file, new HashMap<>());
    }

    /// @param data 表单其他字段
    public Body(HttpFile file, HashMap<String, String> data) throws Exception {
        PointerByReference err = new PointerByReference();
        Gson gson = new Gson();
        this.raw = Session.INSTANCE.Body_new_files(file.getRaw(), gson.toJson(data), err);
        util.check_err_pointer(err);
    }

    @Override
    public void close() {
        if (this.raw == null) return;
        System.out.println("drop body");
        Session.INSTANCE.Body_drop(this.raw);
    }
}
