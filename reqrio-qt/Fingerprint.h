//
// Created by XLX on 2026/5/15.
//

#ifndef REQRIO_QT_FINGERPRINT_H
#define REQRIO_QT_FINGERPRINT_H
#include <QObject>

#include "bindings.h"


class Fingerprint : QObject {
    Q_OBJECT

bindings::Fingerprint *raw_ptr;

public:
    explicit Fingerprint(bindings::Fingerprint *, QObject *parent = nullptr);

    bindings::Fingerprint *take();

    static Fingerprint *fromJa3(const QString &ja3, const QString &token, QObject *parent = nullptr);

    static Fingerprint *fromJa4(const QString &ja4, const QString &token, QObject *parent = nullptr);

    static Fingerprint *fromClientHello(const QByteArray &bs, const QString &token, QObject *parent = nullptr);

    static Fingerprint *fromCustom(const QJsonObject &, const QString &token, QObject *parent = nullptr);

    static Fingerprint *random(const QString &token, QObject *parent = nullptr);
};


#endif //REQRIO_QT_FINGERPRINT_H
