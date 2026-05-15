//
// Created by XLX on 2026/5/15.
//

#include "Fingerprint.h"
#include "Fingerprint.h"

#include "util.h"


Fingerprint::Fingerprint(bindings::Fingerprint *raw, QObject *parent) : QObject(parent) {
    this->raw_ptr = raw;
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
