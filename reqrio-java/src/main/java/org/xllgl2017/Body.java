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

    /// @param json :json请求头
    public Body(JsonElement json) throws Exception {
        byte[] jbs = json.toString().getBytes();
        PointerByReference err = new PointerByReference();
        this.raw = Session.INSTANCE.Body_new(jbs, jbs.length, "application/json", err);
        if (err.getValue() != null) {
            String err_str = err.getValue().getString(0);
            Session.INSTANCE.char_free(err.getValue());
            throw new Exception(err_str);
        }
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
        if (err.getValue() != null) {
            String err_msg = err.getValue().getString(0);
            Session.INSTANCE.char_free(err.getValue());
            throw new Exception(err_msg);
        }

    }

    /// @param text         :请求体文本
    /// @param content_type : 请求头类型
    public Body(String text, String content_type) throws Exception {
        byte[] tbs = text.getBytes();
        PointerByReference err = new PointerByReference();
        this.raw = Session.INSTANCE.Body_new(tbs, tbs.length, content_type, err);
        if (err.getValue() != null) {
            String err_str = err.getValue().getString(0);
            Session.INSTANCE.char_free(err.getValue());
            throw new Exception(err_str);
        }
    }

    /// @param bytes        :二进制请求体
    /// @param content_type : 请求头类型
    public Body(byte[] bytes, String content_type) throws Exception {
        PointerByReference err = new PointerByReference();
        this.raw = Session.INSTANCE.Body_new(bytes, bytes.length, content_type, err);
        if (err.getValue() != null) {
            String err_str = err.getValue().getString(0);
            Session.INSTANCE.char_free(err.getValue());
            throw new Exception(err_str);
        }
    }

    public Body(HttpFile file) throws Exception {
        this(file, new HashMap<>());

    }

    /// @param data 表单其他字段
    public Body(HttpFile file, HashMap<String, String> data) throws Exception {
        PointerByReference err = new PointerByReference();
        Gson gson = new Gson();
        this.raw = Session.INSTANCE.Body_new_files(file.getRaw(), gson.toJson(data), err);
        if (err.getValue() != null) {
            String err_msg = err.getValue().getString(0);
            Session.INSTANCE.char_free(err.getValue());
            throw new Exception(err_msg);
        }
    }

    @Override
    public void close() {
        if (this.raw == null) return;
        System.out.println("drop body");
        Session.INSTANCE.Body_drop(this.raw);
    }
}
