package org.xllgl2017;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;

import java.io.IOException;

interface ReqrioLibrary extends Library {
    Pointer new_http();

    int set_header_json(Pointer req, String header);

    int set_random_fingerprint(Pointer req);

    int add_header(Pointer req, String key, String value);

    int set_alpn(Pointer req, String alpn);

    int set_fingerprint(Pointer req, String tls);

    int set_ja3(Pointer req, String ja3);

    int set_ja4(Pointer req, String ja4);

    int set_proxy(Pointer req, String proxy);

    int set_url(Pointer req, String url);

    int add_param(Pointer req, String name, String value);

    int set_data(Pointer req, String data);

    int set_json(Pointer req, String json);

    int set_bytes(Pointer req, byte[] bytes, int len);

    int set_text(Pointer req, String text);

    int set_timeout(Pointer req, String timeout);

    int set_cookie(Pointer req, String cookie);

    int add_cookie(Pointer req, String name, String value);

    Pointer get(Pointer req);

    Pointer post(Pointer req);

    Pointer options(Pointer req);

    Pointer put(Pointer req);

    Pointer head(Pointer req);

    Pointer delete(Pointer req);

    Pointer trach(Pointer req);

    void destroy(Pointer req);

    void free_pointer(Pointer ptr);

    static ReqrioLibrary loadLibrary() {
        try {
            String tmp_dir = System.getProperty("java.io.tmpdir");
            java.io.File dll_file = new java.io.File(tmp_dir, "reqrio.dll");
            try {
                java.io.InputStream in = ReqrioLibrary.class.getResourceAsStream("/reqrio.dll");
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
            IO.println(dll_file);
            return Native.load(dll_file.getAbsolutePath(), ReqrioLibrary.class);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}