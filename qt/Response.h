//
// Created by XLX on 2026/1/1.
//

#ifndef REQRIO_RESPONSE_H
#define REQRIO_RESPONSE_H

#include "Header.h"


class Response {
    Headers headers;
    QByteArray body;

public:
    Response();

    explicit Response(const char *resp);

    ~Response();

    [[nodiscard]] int length() const;

    [[nodiscard]] QString toString() const;

    [[nodiscard]] QByteArray toByteArray() const;

    [[nodiscard]] QJsonDocument toJson() const;
};


#endif //REQRIO_RESPONSE_H
