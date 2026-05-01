package org.xllgl2017;

import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;

import java.util.HashMap;

public class Url implements AutoCloseable {
    private Pointer raw;

    public Url(String url) throws Exception {
        PointerByReference err = new PointerByReference();
        this.raw = Session.INSTANCE.Url_new(url, err);
        if (err.getValue() != null) {
            String err_msg = err.getValue().getString(0);
            Session.INSTANCE.char_free(err.getValue());
            throw new Exception(err_msg);
        }
    }

    public Url(String url_str, HashMap<String, String> params) throws Exception {
        PointerByReference err = new PointerByReference();
        this.raw = Session.INSTANCE.Url_new(url_str, err);
        if (err.getValue() != null) {
            String err_msg = err.getValue().getString(0);
            Session.INSTANCE.char_free(err.getValue());
            throw new Exception(err_msg);
        }
        for (String key : params.keySet()) {
            this.add_param(key, params.get(key));
        }
    }

    public void add_param(String name, String value) throws Exception {
        if (this.raw == null) throw new Exception("Url had dropped");
        Pointer err = Session.INSTANCE.Url_add_param(this.raw, name, value);
        if (err != null) {
            this.close();
            String err_msg = err.getString(0);
            Session.INSTANCE.char_free(err);
            throw new Exception(err_msg);
        }
    }

    public void remove_param(String name) throws Exception {
        if (this.raw == null) throw new Exception("Url had dropped");
        Pointer err = Session.INSTANCE.Url_remove_param(this.raw, name);
        if (err != null) {
            this.close();
            String err_msg = err.getString(0);
            Session.INSTANCE.char_free(err);
            throw new Exception(err_msg);
        }
    }

    public Pointer getRaw() throws Exception {
        if (this.raw == null) throw new Exception("Url had dropped");
        return raw;
    }

    public void setRaw(Pointer raw) {
        this.raw = raw;
    }

    @Override
    public void close() {
        if (this.raw != null)
            Session.INSTANCE.Url_drop(this.raw);
        this.raw = null;
    }
}
