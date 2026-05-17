//
// Created by XLX on 2026/5/15.
//

#include "Fingerprint.h"

#include <QJsonDocument>


Fingerprint::Fingerprint(bindings::Fingerprint *raw, QObject *parent) : QObject(parent) {
    this->raw_ptr = raw;
}

Fingerprint::Fingerprint(const QString &token, QObject *parent) : QObject(parent) {
    this->raw_ptr = bindings::Fingerprint_new(token.toUtf8());
}


Fingerprint *Fingerprint::fromJa3(const QString &ja3, const QString &token, QObject *parent) {
    char *err = nullptr;
    const auto raw = bindings::Fingerprint_from_ja3(ja3.toUtf8(), token.toUtf8(), &err);
    util::check_err(err);
    return new Fingerprint(raw, parent);
}

Fingerprint *Fingerprint::fromJa4(const QString &ja4, const QString &token, QObject *parent) {
    char *err = nullptr;
    const auto raw = bindings::Fingerprint_from_ja4(ja4.toUtf8(), token.toUtf8(), &err);
    util::check_err(err);
    return new Fingerprint(raw, parent);
}

Fingerprint *Fingerprint::random(const QString &token, QObject *parent) {
    char *err = nullptr;
    const auto raw = bindings::Fingerprint_random(token.toUtf8(), &err);
    util::check_err(err);
    return new Fingerprint(raw, parent);
}

bindings::Fingerprint *Fingerprint::take() {
    bindings::Fingerprint *raw = this->raw_ptr;
    this->raw_ptr = nullptr;
    return raw;
}

Fingerprint *Fingerprint::fromClientHello(const QByteArray &bs, const QString &token, QObject *parent) {
    char *err = nullptr;
    const auto ptr = reinterpret_cast<const uint8_t *>(bs.constData());
    const auto raw = bindings::Fingerprint_from_client_hello(ptr, bs.length(), token.toUtf8(), &err);
    util::check_err(err);
    return new Fingerprint(raw, parent);
}

Fingerprint *Fingerprint::fromCustom(const QJsonObject &custom, const QString &token, QObject *parent) {
    char *err = nullptr;
    const auto raw = bindings::Fingerprint_custom(QJsonDocument(custom).toJson(), token.toUtf8(), &err);
    util::check_err(err);
    return new Fingerprint(raw, parent);
}

void Fingerprint::addCipherSuite(const uint16_t suite) const {
    bindings::Fingerprint_add_cipher_suite(this->raw_ptr, suite);
}

void Fingerprint::addCipherSuites(const QVector<uint16_t> &suites) const {
    for (const uint16_t &suite: suites) {
        this->addCipherSuite(suite);
    }
}

void Fingerprint::addExtension(const uint16_t typ) const {
    bindings::Fingerprint_add_ext(this->raw_ptr, typ);
}


void Fingerprint::addExtensionALPN(const uint16_t typ, const QVector<QString> &alps) const {
    QVector<QByteArray> alps_arrays;
    for (const auto &alpn: alps) {
        alps_arrays.push_back(alpn.toUtf8());
    }
    std::vector<const char *> ptrs;
    ptrs.reserve(alps.size());
    for (const auto &alpn: alps_arrays) {
        ptrs.push_back(alpn.constData());
    }
    bindings::Fingerprint_add_ext_alps(this->raw_ptr, typ, ptrs.data(), alps.length());
}

void Fingerprint::addExtensionGroup(const uint16_t typ, const QVector<uint16_t> &groups) const {
    const auto raw = groups.constData();
    bindings::Fingerprint_add_ext_curve(this->raw_ptr, typ, raw, groups.length());
}


void Fingerprint::addExtensionCompress(const uint16_t typ, const QVector<uint16_t> &methods) const {
    const auto raw = methods.constData();
    bindings::Fingerprint_add_ext_compress(this->raw_ptr, typ, raw, methods.length());
}

void Fingerprint::addExtensionEcPoint(const uint16_t typ, const QVector<uint8_t> &points) const {
    const auto raw = points.constData();
    bindings::Fingerprint_add_ext_ec_point(this->raw_ptr, typ, raw, points.length());
}

void Fingerprint::addExtensionAlgorithm(const uint16_t typ, const QVector<uint16_t> &algorithms) const {
    const auto raw = algorithms.constData();
    bindings::Fingerprint_add_ext_algorithm(this->raw_ptr, typ, raw, algorithms.length());
}

void Fingerprint::addExtension(const uint16_t typ, const QByteArray &bytes) const {
    const auto raw = reinterpret_cast<const uint8_t *>(bytes.constData());
    bindings::Fingerprint_add_ext_bytes(this->raw_ptr, typ, raw, bytes.length());
}

void Fingerprint::addExtensionPadding(const uint16_t typ, const size_t padding) const {
    bindings::Fingerprint_add_ext_padding(this->raw_ptr, typ, padding);
}

void Fingerprint::addH2Setting(const uint16_t flag, const uint32_t value) const {
    bindings::Fingerprint_add_h2_setting(this->raw_ptr, flag, value);
}

void Fingerprint::setH2WindowSize(const uint32_t value) const {
    bindings::Fingerprint_set_h2_window_size(this->raw_ptr, value);
}

void Fingerprint::setH2Priority(const bool priority, const uint8_t weight) const {
    bindings::Fingerprint_set_h2_priority(this->raw_ptr, priority, weight);
}


void Fingerprint::addExtensionVersion(const uint16_t typ, const QVector<uint16_t> &versions) const {
    const auto raw = versions.constData();
    bindings::Fingerprint_add_ext_version(this->raw_ptr, typ, raw, versions.length());
}

Fingerprint::~Fingerprint() {
    if (this->raw_ptr == nullptr)return;
    bindings::Fingerprint_drop(this->raw_ptr);
    this->raw_ptr = nullptr;
}
