//
// Created by XLX on 2026/1/21.
//

#ifndef REQRIO_QT_HEADER_H
#define REQRIO_QT_HEADER_H
#include <QJsonObject>
#include <QJsonArray>
#include <qlist.h>
#include <qstring.h>
#include "bindings.h"
#include "Cookie.h"


class Header {
    QString name;
    QString value;

public:
    Header(const QString &name, const QString &value);
};

class Headers {
    Method method = GET;
    QString agreement;
    QString uri;
    int status = -1;
    QList<Cookie> cookies;
    QList<Header> keys;

    static Method to_method(const QString &name);

public:
    Headers() = default;

    explicit Headers(const QJsonObject &headers);

    ~Headers();

    [[nodiscard]] int getStatus() const;
};

#endif //REQRIO_QT_HEADER_H
