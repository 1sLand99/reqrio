//
// Created by XLX on 2026/1/1.
//

#ifndef UNTITLED_REQRIO_H
#define UNTITLED_REQRIO_H

#include "Response.h"
#include "Timeout.h"
#include "util.h"
#include "bindings.h"
#include "Body.h"
#include "Fingerprint.h"
#include "Url.h"

using namespace std;

enum ALPN {
    HTTP20,
    HTTP11,
};


class Session : QObject {
    Q_OBJECT
    bindings::ScReq *req = nullptr;

public:
    explicit Session(QObject *parent = nullptr);

    ~Session() override;

    explicit Session(ALPN alpn, bool verify = true, QObject *parent = nullptr);

    void setHeader(const QJsonDocument &header) const;

    void addHeader(const QString &name, const QString &value) const;

    void setAlpn(ALPN alpn) const;

    void setVerify(bool verify) const;

    void setKeyLog(const QString &key_log) const;

    void setProxy(const QString &proxy) const;

    void setTimeout(const Timeout &timeout) const;

    void setCookie(const QString &cookie) const;

    void addCookie(const QString &name, const QString &value) const;

    void setFingerprint(Fingerprint *fingerprint) const;

    // void setCallback(bindings::Callback callback) const;
    [[nodiscard]] Response send(bindings::Method method, Url *url, Body *body) const;

    [[nodiscard]] Response get(Url *, Body *) const;

    [[nodiscard]] Response post(Url *, Body *) const;

    [[nodiscard]] Response put(Url *, Body *) const;

    [[nodiscard]] Response options(Url *, Body *) const;

    [[nodiscard]] Response head(Url *, Body *) const;

    [[nodiscard]] Response delete_(Url *, Body *) const;

    [[nodiscard]] Response trace(Url *, Body *) const;

    [[nodiscard]] Response patch(Url *, Body *) const;

private:
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
