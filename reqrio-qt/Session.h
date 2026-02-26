//
// Created by XLX on 2026/1/1.
//

#ifndef UNTITLED_REQRIO_H
#define UNTITLED_REQRIO_H

#include "Response.h"
#include "Timeout.h"
using namespace std;

enum ALPN {
    HTTP20,
    HTTP11,
};


class Session {
    bindings::ScReq *req = nullptr;

public:
    explicit Session();

    ~Session();

    explicit Session(ALPN alpn, bool rand_tls = false, const QString &token = "");

    void set_header_json(const QString &header) const;

    void add_header(const QString &name, const QString &value) const;

    void set_alpn(ALPN alpn) const;

    void set_proxy(const QString &proxy) const;

    void add_param(const QString &name, const QString &value) const;

    void set_data(const QString &data) const;

    void set_json(const QString &json) const;

    void set_bytes(const char *bytes) const;

    void set_text(const QString &content_type) const;

    void set_timeout(const Timeout &timeout) const;

    void set_cookie(const QString &cookie) const;

    void add_cookie(const QString &name, const QString &value) const;

    void set_fingerprint(const QString &fingerprint, const QString &token) const;

    void set_ja3(const QString &ja3, const QString &token) const;

    void set_ja4(const QString &ja4, const QString &token) const;

    void set_callback(bindings::Callback callback);

    [[nodiscard]] Response get() const;

    [[nodiscard]] Response post() const;

    [[nodiscard]] Response put() const;

    [[nodiscard]] Response options() const;

    [[nodiscard]] Response head() const;

    [[nodiscard]] Response delete_() const;

    [[nodiscard]] Response trace() const;

    [[nodiscard]] Response patch() const;

    void setUrl(const QString &url) const;

    void close() const;

private:
    [[nodiscard]] Response send(bindings::Method method) const;

    static const char *alpn_str(ALPN alpn) {
        switch (alpn) {
            case HTTP20:
                return "h2";
            case HTTP11:
                return "http/1.1";
        }
        return "";
    };
};


#endif //UNTITLED_REQRIO_H
