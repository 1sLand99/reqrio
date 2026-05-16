//
// Created by XLX on 2026/1/1.
//

#include "Session.h"

#include <QJsonDocument>


Session::Session(QObject *parent) : QObject(parent) {
    this->req = bindings::ScReq_new();
}

Session::Session(const ALPN alpn, const bool verify, const bool auto_redirect, QObject *parent) : Session(parent) {
    this->setAlpn(alpn);
    this->setVerify(verify);
    this->setRedirect(auto_redirect);
}

void Session::setHeader(const QJsonDocument &header) const {
    util::check_err(bindings::ScReq_set_header_json(this->req, header.toJson().data()));
}

void Session::addHeader(const QString &name, const QString &value) const {
    util::check_err(bindings::ScReq_add_header(this->req, name.toUtf8(), value.toUtf8()));
}

void Session::setAlpn(const ALPN alpn) const {
    const char *alpn_str = Session::alpn_str(alpn);
    util::check_err(bindings::ScReq_set_alpn(this->req, alpn_str));
}

void Session::setVerify(const bool verify) const {
    util::check_err(bindings::ScReq_set_verify(this->req, verify));
}

void Session::setRedirect(const bool auto_redirect) const {
    util::check_err(bindings::ScReq_set_redirect(this->req, auto_redirect));
}

void Session::setKeyLog(const QString &key_log) const {
    util::check_err(bindings::ScReq_set_key_log(this->req, key_log.toUtf8()));
}

void Session::setProxy(const QString &proxy) const {
    util::check_err(bindings::ScReq_set_proxy(this->req, proxy.toUtf8()));
}


void Session::setTimeout(const Timeout &timeout) const {
    const auto json = QJsonDocument(timeout.toJson());
    util::check_err(bindings::ScReq_set_timeout(this->req, json.toJson(QJsonDocument::Compact)));
}

void Session::setCookie(const QString &cookie) const {
    util::check_err(bindings::ScReq_set_cookie(this->req, cookie.toUtf8()));
}

void Session::addCookie(const QString &name, const QString &value) const {
    util::check_err(bindings::ScReq_add_cookie(this->req, name.toUtf8(), value.toUtf8()));
}

void Session::setFingerprint(Fingerprint *fingerprint) const {
    util::check_err(bindings::ScReq_set_fingerprint(this->req, fingerprint->take()));
    delete fingerprint;
}

Response Session::send(const bindings::Method method, Url *url, Body *body) const {
    char *err = nullptr;
    const auto resp_ptr = bindings::ScReq_stream_io(this->req, method, url->take(), body->take(), &err);
    delete url;
    delete body;
    util::check_err(err);
    return Response(resp_ptr);
}

// void Session::setCallback(const bindings::Callback callback) const {
//     bindings::ScReq_set_callback(this->req, callback);
// }


Response Session::get(Url *url, Body *body) const {
    return send(bindings::GET, url, body);
}

Response Session::get(const QString &url, Body *body) const {
    return this->get(new Url(url), body);
}

Response Session::get(const QString &url) const {
    return this->get(url, new Body());
}

Response Session::post(Url *url, Body *body) const {
    return send(bindings::POST, url, body);
}

Response Session::post(const QString &url, Body *body) const {
    return post(new Url(url), body);
}

Response Session::post(const QString &url, const QJsonDocument &body) const {
    return post(url, new Body(body));
}

Response Session::post(const QString &url, const QMap<QString, QString> &body) const {
    return post(url, new Body(body));
}

Response Session::put(Url *url, Body *body) const {
    return send(bindings::PUT, url, body);
}

Response Session::head(Url *url, Body *body) const {
    return send(bindings::HEAD, url, body);
}

Response Session::options(Url *url, Body *body) const {
    return send(bindings::OPTIONS, url, body);
}

Response Session::trace(Url *url, Body *body) const {
    return send(bindings::TRACE, url, body);
}

Response Session::delete_(Url *url, Body *body) const {
    return send(bindings::DELETE, url, body);
}

Response Session::patch(Url *url, Body *body) const {
    return send(bindings::PATCH, url, body);
}


Session::~Session() {
    if (this->req == nullptr) return;
    bindings::ScReq_drop(this->req);
    this->req = nullptr;
}
