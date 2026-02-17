#pragma once

#include <cstdint>

namespace bindings {
    extern "C" {
    enum Method {
        GET = 0,
        POST = 1,
        PUT = 2,
        HEAD = 3,
        DELETE = 4,
        OPTIONS = 5,
        TRACE = 6,
        CONNECT = 7,
    };

    struct ScReq;

    ScReq *ScReq_new();

    int ScReq_set_header_json(ScReq *req, const char *header);

    int ScReq_add_header(ScReq *req, const char *key, const char *value);

    int ScReq_set_alpn(ScReq *req, const char *alpn);

    int ScReq_set_random_fingerprint(ScReq *req, const char *token);

    int ScReq_set_fingerprint(ScReq *req, const char *fingerprint, const char *token);

    int ScReq_set_ja3(ScReq *req, const char *ja3, const char *token);

    int ScReq_set_ja4(ScReq *req, const char *ja4, const char *token);

    int ScReq_set_proxy(ScReq *req, const char *proxy);

    int ScReq_set_url(ScReq *req, const char *url);

    int ScReq_add_param(ScReq *req, const char *name, const char *value);

    int ScReq_set_data(ScReq *req, const char *data);

    int ScReq_set_json(ScReq *req, const char *json);

    int ScReq_set_bytes(ScReq *req, const char *bytes, uint32_t len);

    int ScReq_set_text(ScReq *req, const char *text);

    int ScReq_set_timeout(ScReq *req, const char *timeout);

    int ScReq_set_cookie(ScReq *req, const char *cookie);

    int ScReq_add_cookie(ScReq *req, const char *name, const char *value);

    typedef void (*Callback)(const char *data, uint32_t len);

    int ScReq_set_callback(ScReq *req, Callback callback);

    int ScReq_reconnect(ScReq *req);

    char *ScReq_stream_io(ScReq *req, Method method);

    void ScReq_drop(ScReq *req);

    void char_free(char *p);

    struct WsBuilder;

    WsBuilder *ws_build();

    int ws_add_header(WsBuilder *builder, const char *name, const char *value);

    int ws_set_proxy(WsBuilder *builder, const char *proxy);

    int ws_set_url(WsBuilder *builder, const char *url);

    int ws_set_uri(WsBuilder *builder, const char *uri);

    struct WS_SOCKET;

    WS_SOCKET *ws_open(WsBuilder *builder);

    WS_SOCKET *ws_open_raw(const char *url, const char *raw);

    char *ws_read(WS_SOCKET *ws);

    int ws_write(WS_SOCKET *ws, int opcode, bool mask, const char *msg);

    void ws_close(WS_SOCKET *ws);
    }
}
