//
// Created by XLX on 2026/1/21.
//
#include <QJsonArray>
#include "Header.h"

Header::Header(const QString &name, const QString &value) {
    this->name = name;
    this->value = value;
}

bindings::Method Headers::to_method(const QString &name) {
    if (name == "GET") {
        return bindings::GET;
    }
    if (name == "POST") {
        return bindings::POST;
    }
    if (name == "PUT") {
        return bindings::PUT;
    }
    if (name == "DELETE") {
        return bindings::DELETE;
    }
    if (name == "HEAD") {
        return bindings::HEAD;
    }
    if (name == "OPTIONS") {
        return bindings::OPTIONS;
    }
    if (name == "TRACE") {
        return bindings::TRACE;
    }
    return bindings::GET;
}

Headers::Headers(const QJsonObject &headers) {
    this->uri = headers.value("uri").toString();
    this->method = to_method(headers.value("method").toString());
    this->status = headers.value("status").toInt();
    this->agreement = headers.value("agreement").toString();
    QJsonObject kvs = headers.value("keys").toObject();
    if (kvs.contains("Set-Cookie")) {
        QJsonArray cks = kvs.value("Set-Cookie").toArray();
        for (auto cookie: cks) {
            this->cookies.append(Cookie(cookie.toObject()));
        }
    }
    if (kvs.contains("set-cookie")) {
        QJsonArray cks = kvs.value("set-cookie").toArray();
        for (auto cookie: cks) {
            this->cookies.append(Cookie(cookie.toObject()));
        }
    }
    for (QString k: kvs.keys()) {
        this->keys.append(Header(k, kvs.value(k).toString()));
    }
}


int Headers::getStatus() const {
    return this->status;
}

Headers::~Headers() {
    this->keys.clear();
    this->cookies.clear();
}
