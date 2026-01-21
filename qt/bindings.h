#pragma once

#include <cstdint>

enum Method {
    GET,
    POST,
    PUT,
    OPTIONS,
    DELETE,
    TRACH,
    HEAD
};

namespace bindings {
    extern "C" {
    struct ScReq;

    ScReq *new_http();

    int set_header_json(ScReq *req, const char *header);

    int set_random_fingerprint(ScReq *req);

    int add_header(ScReq *req, const char *key, const char *value);

    int set_alpn(ScReq *req, const char *alpn);

    int set_fingerprint(ScReq *req, const char *fingerprint);

    int set_ja3(ScReq *req, const char *ja3);

    int set_ja4(ScReq *req, const char *ja4);

    int set_proxy(ScReq *req, const char *proxy);

    int set_url(ScReq *req, const char *url);

    int add_param(ScReq *req, const char *name, const char *value);

    int set_data(ScReq *req, const char *data);

    int set_json(ScReq *req, const char *json);

    int set_bytes(ScReq *req, const char *bytes, uint32_t len);

    int set_text(ScReq *req, const char *text);

    int set_timeout(ScReq *req, const char *timeout);

    int set_cookie(ScReq *req, const char *cookie);

    int add_cookie(ScReq *req, const char *name, const char *value);

    int reconnect(ScReq *req);

    char *get(ScReq *req);

    char *post(ScReq *req);

    char *put(ScReq *req);

    char *options(ScReq *req);

    char *head(ScReq *req);

    // #define delete delete_
    //     char *delete_(ScReq *req);

    char *trach(ScReq *req);

    void destroy(ScReq *req);

    void free_pointer(char *p);
    }
}
