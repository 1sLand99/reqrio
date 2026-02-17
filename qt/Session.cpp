//
// Created by XLX on 2026/1/1.
//

#include "Session.h"

#include <QJsonDocument>

#include "bindings.h"

Session::Session() {
    this->req = bindings::ScReq_new();
}


Session::Session(const ALPN alpn, bool rand_tls, const QString &token) {
    this->req = bindings::ScReq_new();
    bindings::ScReq_set_alpn(this->req, alpn_str(alpn));
    if (rand_tls && !token.isEmpty())
        bindings::ScReq_set_random_fingerprint(this->req, token.toUtf8());
}

void Session::set_header_json(const QString &header) const {
    bindings::ScReq_set_header_json(this->req, header.toUtf8());
}

void Session::add_header(const QString &name, const QString &value) const {
    bindings::ScReq_add_header(this->req, name.toUtf8(), value.toUtf8());
}

void Session::set_alpn(const ALPN alpn) const {
    const char *alpn_str = Session::alpn_str(alpn);
    bindings::ScReq_set_alpn(this->req, alpn_str);
}

void Session::set_proxy(const QString &proxy) const {
    bindings::ScReq_set_proxy(this->req, proxy.toUtf8());
}

void Session::setUrl(const QString &url) const {
    bindings::ScReq_set_url(this->req, url.toUtf8());
}

void Session::add_param(const QString &name, const QString &value) const {
    bindings::ScReq_add_param(this->req, name.toUtf8(), value.toUtf8());
}

void Session::set_data(const QString &data) const {
    bindings::ScReq_set_data(this->req, data.toUtf8());
}

void Session::set_json(const QString &json) const {
    bindings::ScReq_set_json(this->req, json.toUtf8());
}

void Session::set_bytes(const char *bytes) const {
    bindings::ScReq_set_bytes(this->req, bytes, sizeof(bytes));
}

void Session::set_text(const QString &content_type) const {
    bindings::ScReq_set_text(this->req, content_type.toUtf8());
}

void Session::set_timeout(const Timeout &timeout) const {
    const auto json = QJsonDocument(timeout.toJson());
    bindings::ScReq_set_timeout(this->req, json.toJson(QJsonDocument::Compact));
}

void Session::set_cookie(const QString &cookie) const {
    bindings::ScReq_set_cookie(this->req, cookie.toUtf8());
}

void Session::add_cookie(const QString &name, const QString &value) const {
    bindings::ScReq_add_cookie(this->req, name.toUtf8(), value.toUtf8());
}

void Session::set_fingerprint(const QString &fingerprint, const QString &token) const {
    bindings::ScReq_set_fingerprint(this->req, fingerprint.toUtf8(), token.toUtf8());
}

void Session::set_ja3(const QString &ja3, const QString &token) const {
    bindings::ScReq_set_ja3(this->req, ja3.toUtf8(), token.toUtf8());
}

void Session::set_ja4(const QString &ja4, const QString &token) const {
    bindings::ScReq_set_ja4(this->req, ja4.toUtf8(), token.toUtf8());
}

Response Session::send(const bindings::Method method) const {
    char *ptr = bindings::ScReq_stream_io(this->req, method);
    if (ptr == nullptr) { return {}; }
    Response resp(ptr);
    bindings::char_free(ptr);
    return resp;
}

void Session::set_callback(bindings::Callback callback) {
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

Response Session::trach() const {
    return send(bindings::TRACE);
}

Response Session::delete_() const {
    return send(bindings::DELETE);
}

void Session::close() const {
    if (this->req == nullptr)return;
    bindings::ScReq_drop(this->req);
}

Session::~Session() {
    this->close();
}
