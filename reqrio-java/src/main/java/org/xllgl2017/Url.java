package org.xllgl2017;

import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;

import java.util.HashMap;

public class Url implements AutoCloseable {
    private Pointer raw;

    /// 初始化
    ///
    /// @param url :请求地址
    public Url(String url) throws Exception {
        PointerByReference err = new PointerByReference();
        this.raw = Session.INSTANCE.Url_new(url, err);
        util.check_err_pointer(err);
    }

    /// @param sni :域名
    public Url(String url, String sni) throws Exception {
        this(url);
        this.setSni(sni);
    }

    /// @param params url请求参数，value应为未编码
    public Url(String url_str, HashMap<String, String> params) throws Exception {
        this(url_str);
        for (String key : params.keySet()) {
            this.add_param(key, params.get(key));
        }
    }

    /// 添加一个请求参数，若这个值已存在则会被覆盖
    ///
    /// @param name  :参数名
    /// @param value :参数值
    public void add_param(String name, String value) throws Exception {
        if (this.raw == null) throw new Exception("Url had dropped");
        try {
            util.check_err(Session.INSTANCE.Url_add_param(this.raw, name, value));
        } catch (Exception e) {
            close();
            throw e;
        }
    }

    /// 删除一个参数
    ///
    /// @param name :待删除的参数名
    public void remove_param(String name) throws Exception {
        if (this.raw == null) throw new Exception("Url had dropped");
        try {
            util.check_err(Session.INSTANCE.Url_remove_param(this.raw, name));
        } catch (Exception e) {
            close();
            throw e;
        }
    }

    public Pointer getRaw() throws Exception {
        if (this.raw == null) throw new Exception("Url had dropped");
        return raw;
    }

    public void setRaw(Pointer raw) {
        this.raw = raw;
    }

    /// @param sni :域名，在使用ip url时设置
    public void setSni(String sni) throws Exception {
        if (this.raw == null) throw new Exception("Url had dropped");
        try {
            util.check_err(Session.INSTANCE.Url_set_sni(this.raw, sni));
        } catch (Exception e) {
            close();
            throw e;
        }
    }

    @Override
    public void close() {
        if (this.raw != null)
            Session.INSTANCE.Url_drop(this.raw);
        this.raw = null;
    }
}
