package org.xllgl2017;

import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;

public class HttpFile implements AutoCloseable {
    private Pointer raw;

    public HttpFile() {
        this.raw = Session.INSTANCE.HttpFile_new();
    }


    public void addFile(String path) throws Exception {
        this.addFile(path, "file");
    }

    public void addFile(String path, String fieldName) throws Exception {
        this.addFile(path, fieldName, null);
    }

    /// @param path         :文件路径，相对路径或绝对路径
    /// @param fieldName    :文件所在表单的属性名
    /// @param content_type :文件内容类型
    public void addFile(String path, String fieldName, String content_type) throws Exception {
        PointerByReference err = new PointerByReference();
        Pointer form = Session.INSTANCE.FileForm_new(path, fieldName, content_type, err);
        if (err.getValue() != null) {
            this.close();
            String err_msg = err.getValue().getString(0);
            Session.INSTANCE.char_free(err.getValue());
            throw new Exception(err_msg);
        }
        Pointer err1 = Session.INSTANCE.HttpFile_add_form(this.raw, form);
        if (err1 != null) {
            this.close();
            String err_msg = err1.getString(0);
            Session.INSTANCE.char_free(err1);
            throw new Exception(err_msg);
        }
    }

    public void setRaw(Pointer raw) {
        this.raw = raw;
    }

    public Pointer getRaw() {
        return raw;
    }

    @Override
    public void close() {
        if (this.raw == null) return;
        Session.INSTANCE.HttpFile_drop(this.raw);
        this.raw = null;
    }
}
