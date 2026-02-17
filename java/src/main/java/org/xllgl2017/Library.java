package org.xllgl2017;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;

import java.io.IOException;

interface ReqrioLibrary extends Library {
    Pointer ScReq_new();

    int ScReq_set_header_json(Pointer req, String header);

    int ScReq_add_header(Pointer req, String key, String value);

    int ScReq_set_alpn(Pointer req, String alpn);

    int ScReq_set_random_fingerprint(Pointer req, String token);

    int ScReq_set_fingerprint(Pointer req, String tls, String token);

    int ScReq_set_ja3(Pointer req, String ja3, String token);

    int ScReq_set_ja4(Pointer req, String ja4, String token);

    int ScReq_set_proxy(Pointer req, String proxy);

    int ScReq_set_url(Pointer req, String url);

    int ScReq_add_param(Pointer req, String name, String value);

    int ScReq_set_data(Pointer req, String data);

    int ScReq_set_json(Pointer req, String json);

    int ScReq_set_bytes(Pointer req, byte[] bytes, int len);

    int ScReq_set_text(Pointer req, String text);

    int ScReq_set_timeout(Pointer req, String timeout);

    int ScReq_set_cookie(Pointer req, String cookie);

    int ScReq_add_cookie(Pointer req, String name, String value);

    int ScReq_set_callback(Pointer req, ScReqCallback cb);

    int ScReq_reconnect(Pointer req);

    Pointer ScReq_stream_io(Pointer req, int method);

    void ScReq_drop(Pointer req);

    void char_free(Pointer ptr);

    Pointer ws_build();

    int ws_add_header(Pointer builder, String name, String value);

    int ws_set_proxy(Pointer builder, String proxy);

    int ws_set_url(Pointer builder, String url);

    int ws_set_uri(Pointer builder, String uri);

    Pointer ws_open(Pointer builder);

    Pointer ws_open_raw(String url, String raw);

    Pointer ws_read(Pointer ws);

    int ws_write(Pointer ws, int opcode, boolean mask, String msg);

    void ws_close(Pointer ws);

    static ReqrioLibrary loadLibrary() {
        try {
            String os_name = System.getProperty("os.name").toLowerCase();
            String dll_name;
            if (os_name.contains("win"))
                dll_name = "reqrio.dll";
            else if (os_name.contains("nux") || os_name.contains("nix"))
                dll_name = "libreqrio.os";
            else throw new Exception("unsupported system");
            String tmp_dir = System.getProperty("java.io.tmpdir");
            java.io.File dll_file = new java.io.File(tmp_dir, dll_name);
            try {
                java.io.InputStream in = ReqrioLibrary.class.getResourceAsStream("/" + dll_name);
                java.io.OutputStream out = new java.io.FileOutputStream(dll_file);
                byte[] buffer = new byte[4096];
                int read;
                while ((read = in.read(buffer)) != -1) {
                    out.write(buffer, 0, read);
                }
                out.flush();
                out.close();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            System.out.println(dll_file);
            return Native.load(dll_file.getAbsolutePath(), ReqrioLibrary.class);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}