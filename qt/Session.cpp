//
// Created by XLX on 2026/1/1.
//

#include "Session.h"

#include <QJsonDocument>

#include "bindings.h"

Session::Session() {
    this->req = bindings::new_http();
}


Session::Session(const ALPN alpn) {
    this->req = bindings::new_http();
    bindings::set_alpn(this->req, alpn_str(alpn));
}

void Session::set_header_json(const QString &header) const {
    bindings::set_header_json(this->req, header.toUtf8());
}

void Session::add_header(const QString &name, const QString &value) const {
    bindings::add_header(this->req, name.toUtf8(), value.toUtf8());
}

void Session::set_alpn(const ALPN alpn) const {
    const char *alpn_str = Session::alpn_str(alpn);
    bindings::set_alpn(this->req, alpn_str);
}

void Session::set_proxy(const QString &proxy) const {
    bindings::set_proxy(this->req, proxy.toUtf8());
}

void Session::setUrl(const QString &url) const {
    bindings::set_url(this->req, url.toUtf8());
}

void Session::add_param(const QString &name, const QString &value) const {
    bindings::add_param(this->req, name.toUtf8(), value.toUtf8());
}

void Session::set_data(const QString &data) const {
    bindings::set_data(this->req, data.toUtf8());
}

void Session::set_json(const QString &json) const {
    bindings::set_json(this->req, json.toUtf8());
}

void Session::set_bytes(const char *bytes) const {
    bindings::set_bytes(this->req, bytes, sizeof(bytes));
}

void Session::set_text(const QString &content_type) const {
    bindings::set_text(this->req, content_type.toUtf8());
}

void Session::set_timeout(const Timeout &timeout) const {
    const auto json = QJsonDocument(timeout.toJson());
    bindings::set_timeout(this->req, json.toJson(QJsonDocument::Compact));
}

void Session::set_cookie(const QString &cookie) const {
    bindings::set_cookie(this->req, cookie.toUtf8());
}

void Session::add_cookie(const QString &name, const QString &value) const {
    bindings::add_cookie(this->req, name.toUtf8(), value.toUtf8());
}

void Session::set_fingerprint(const QString &fingerprint) const {
    bindings::set_fingerprint(this->req, fingerprint.toUtf8());
}

Response Session::send(const Method method) const {
    char *ptr = nullptr;
    switch (method) {
        case GET:
            ptr = bindings::get(this->req);
            break;
        case POST:
            ptr = bindings::post(this->req);
            break;
        case PUT:
            ptr = bindings::put(this->req);
            break;
        case DELETE:
            // ptr = bindings::delete_(this->req);
            break;
        case OPTIONS:
            ptr = bindings::options(this->req);
            break;
        case TRACH:
            ptr = bindings::trach(this->req);
            break;
        case HEAD:
            ptr = bindings::head(this->req);
            break;
    }
    if (ptr == nullptr) { return {}; }
    Response resp(ptr);
    bindings::free_pointer(ptr);
    return resp;
}


Response Session::get() const {
    return send(GET);
}


Response Session::post() const {
    return send(POST);
}

Response Session::put() const {
    return send(PUT);
}

Response Session::head() const {
    return send(HEAD);
}

Response Session::options() const {
    return send(OPTIONS);
}

Response Session::trach() const {
    return send(TRACH);
}

Response Session::delete_() const {
    return send(DELETE);
}

void Session::close() const {
    bindings::destroy(this->req);
}
