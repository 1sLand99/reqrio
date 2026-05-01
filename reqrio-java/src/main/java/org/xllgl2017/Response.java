package org.xllgl2017;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.reflect.TypeToken;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.LongByReference;
import com.sun.jna.ptr.PointerByReference;

import java.util.ArrayList;
import java.util.List;

public class Response implements AutoCloseable {
    private Pointer raw;

    public Response(Pointer raw) {
        this.raw = raw;

    }

    public int status_code() throws Exception {
        if (this.raw == null) throw new Exception("Response is dropped");
        PointerByReference err = new PointerByReference();
        int code = Session.INSTANCE.Response_status_code(this.raw, err);
        if (err.getValue() != null) {
            String err_msg = err.getValue().getString(0);
            Session.INSTANCE.char_free(err.getValue());
            throw new Exception(err_msg);
        }
        return code;

    }

    public String get_header(String name) throws Exception {
        if (this.raw == null) throw new Exception("Response is dropped");
        PointerByReference err = new PointerByReference();
        Pointer value = Session.INSTANCE.Response_get_header(this.raw, name, err);
        if (err.getValue() != null) {
            String err_msg = err.getValue().getString(0);
            Session.INSTANCE.char_free(err.getValue());
            throw new Exception(err_msg);
        }
        String value_str = value.getString(0);
        Session.INSTANCE.char_free(value);
        return value_str;
    }

    public String location() throws Exception {
        return this.get_header("location");
    }

    public byte[] bytes() throws Exception {
        if (this.raw == null) throw new Exception("Response is dropped");
        PointerByReference err = new PointerByReference();
        LongByReference len = new LongByReference();
        Pointer ptr = Session.INSTANCE.Response_bytes(this.raw, len, err);
        if (err.getValue() != null) {
            String err_msg = err.getValue().getString(0);
            Session.INSTANCE.char_free(err.getValue());
            throw new Exception(err_msg);
        }
        return ptr.getByteArray(0, (int) len.getValue());
    }

    public String text() throws Exception {
        return new String(this.bytes());
    }

    public JsonElement json() throws Exception {
        Gson gson = new Gson();
        return gson.fromJson(this.text(), JsonElement.class);
    }

    public Pointer getRaw() {
        return raw;
    }

    public ArrayList<Cookie> getCookies() throws Exception {
        PointerByReference err = new PointerByReference();
        Pointer ptr = Session.INSTANCE.Response_cookies(this.raw, err);
        if (err.getValue() != null) {
            String err_msg = err.getValue().getString(0);
            Session.INSTANCE.char_free(err.getValue());
            throw new Exception(err_msg);
        }
        String cookie_str = ptr.getString(0);
        Session.INSTANCE.char_free(ptr);
        Gson gson = new Gson();
        return gson.fromJson(cookie_str, new TypeToken<ArrayList<Cookie>>() {
        }.getType());
    }

    @Override
    public void close() {
        if (this.raw == null) return;
        Session.INSTANCE.Response_drop(this.raw);
        this.raw = null;
    }
}
