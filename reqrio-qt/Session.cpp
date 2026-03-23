//
// Created by XLX on 2026/1/1.
//

#include "Session.h"

#include <QJsonDocument>

#include "bindings.h"

Session::Session() {
    this->req = bindings::ScReq_new();
}


Session::Session(const ALPN alpn, const bool rand_tls, const QString &token, const bool verify) {
    this->req = bindings::ScReq_new();
    bindings::ScReq_set_alpn(this->req, alpn_str(alpn));
    if (rand_tls && !token.isEmpty())
        bindings::ScReq_set_random_fingerprint(this->req, token.toUtf8());
    bindings::ScReq_set_verify(this->req, verify);
}

void Session::setHeaderJson(const QString &header) const {
    bindings::ScReq_set_header_json(this->req, header.toUtf8());
}

void Session::addHeader(const QString &name, const QString &value) const {
    bindings::ScReq_add_header(this->req, name.toUtf8(), value.toUtf8());
}

void Session::setAlpn(const ALPN alpn) const {
    const char *alpn_str = Session::alpn_str(alpn);
    bindings::ScReq_set_alpn(this->req, alpn_str);
}

void Session::setProxy(const QString &proxy) const {
    bindings::ScReq_set_proxy(this->req, proxy.toUtf8());
}

void Session::setUrl(const QString &url) const {
    bindings::ScReq_set_url(this->req, url.toUtf8());
}

void Session::addParam(const QString &name, const QString &value) const {
    bindings::ScReq_add_param(this->req, name.toUtf8(), value.toUtf8());
}

void Session::setData(const QString &data) const {
    this->setBytes(reinterpret_cast<const uint8_t *>(data.toUtf8().data()), "application/x-www-form-urlencoded");
}

void Session::setJson(const QString &json) const {
    this->setBytes(reinterpret_cast<const uint8_t *>(json.toUtf8().data()), "application/json");
}

void Session::setBytes(const uint8_t *bytes, const QString &ct) const {
    bindings::ScReq_set_bytes(this->req, bytes, sizeof(bytes), ct.toUtf8());
}

void Session::setText(const QString &text) const {
    this->setBytes(reinterpret_cast<const uint8_t *>(text.toUtf8().data()), "text/plain");
}

void Session::setContextType(const QString &contextType) const {
    bindings::ScReq_set_context_type(this->req, contextType.toUtf8());
}

void Session::setTimeout(const Timeout &timeout) const {
    const auto json = QJsonDocument(timeout.toJson());
    bindings::ScReq_set_timeout(this->req, json.toJson(QJsonDocument::Compact));
}

void Session::setCookie(const QString &cookie) const {
    bindings::ScReq_set_cookie(this->req, cookie.toUtf8());
}

void Session::addCookie(const QString &name, const QString &value) const {
    bindings::ScReq_add_cookie(this->req, name.toUtf8(), value.toUtf8());
}

void Session::setFingerprint(const QString &fingerprint, const QString &token) const {
    bindings::ScReq_set_fingerprint(this->req, fingerprint.toUtf8(), token.toUtf8());
}

void Session::setJa3(const QString &ja3, const QString &token) const {
    bindings::ScReq_set_ja3(this->req, ja3.toUtf8(), token.toUtf8());
}

void Session::setJa4(const QString &ja4, const QString &token) const {
    bindings::ScReq_set_ja4(this->req, ja4.toUtf8(), token.toUtf8());
}

Response Session::send(const bindings::Method method) const {
    char *ptr = bindings::ScReq_stream_io(this->req, method);
    if (ptr == nullptr) { return {}; }
    Response resp(ptr);
    bindings::char_free(ptr);
    return resp;
}

void Session::setCallback(const bindings::Callback callback) const {
    bindings::ScReq_set_callback(this->req, callback);
}


Response Session::get() const {
    return send(bindings::GET);
}


Response Session::post() const {
    return send(bindings::POST);
}

Response Session::put() const {
    return send(bindings::PUT);
}

Response Session::head() const {
    return send(bindings::HEAD);
}

Response Session::options() const {
    return send(bindings::OPTIONS);
}

Response Session::trace() const {
    return send(bindings::TRACE);
}

Response Session::delete_() const {
    return send(bindings::DELETE);
}

Response Session::patch() const {
    return send(bindings::PATCH);
}

void Session::close() const {
    if (this->req == nullptr)return;
    bindings::ScReq_drop(this->req);
}

Session::~Session() {
    this->close();
}
