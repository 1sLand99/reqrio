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

    explicit Session(ALPN alpn, bool rand_tls = false, const QString &token = "", bool verify = true);

    void setHeaderJson(const QString &header) const;

    void addHeader(const QString &name, const QString &value) const;

    void setAlpn(ALPN alpn) const;

    void setProxy(const QString &proxy) const;

    void addParam(const QString &name, const QString &value) const;

    void setData(const QString &data) const;

    void setJson(const QString &json) const;

    void setBytes(const uint8_t *bytes, const QString &ct = "application/octet-stream") const;

    void setText(const QString &text) const;

    void setContextType(const QString &contextType) const;

    void setTimeout(const Timeout &timeout) const;

    void setCookie(const QString &cookie) const;

    void addCookie(const QString &name, const QString &value) const;

    void setFingerprint(const QString &fingerprint, const QString &token) const;

    void setJa3(const QString &ja3, const QString &token) const;

    void setJa4(const QString &ja4, const QString &token) const;

    void setCallback(bindings::Callback callback) const;

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
