//
// Created by XLX on 2026/1/1.
//

#include "Response.h"

#include <qdebug.h>
#include <QJsonDocument>
#include <QJsonObject>


Response::Response() = default;


Response::Response(const char *resp) {
    QByteArray data = QByteArray::fromHex(resp);
    QJsonObject res = QJsonDocument::fromJson(data).object();
    this->headers = Headers(res.value("header").toObject());
    this->body = QByteArray::fromHex(res.value("body").toString().toUtf8());
}

int Response::length() const {
    return this->body.length();
}

QString Response::toString() const {
    return QString::fromUtf8(this->body);
}

QByteArray Response::toByteArray() const {
    return this->body;
}

QJsonDocument Response::toJson() const {
    return QJsonDocument::fromJson(this->body);
}

Response::~Response() {
    this->body.clear();
}
