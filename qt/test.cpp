//
// Created by XLX on 2026/1/1.
//

#include <iostream>
#include <ostream>

#include "Session.h"

void callback(const char *data, uint32_t len) {
    QByteArray bytes = QByteArray::fromRawData(data, len);
    qDebug() << bytes.length();
}

int main(int argc, char *argv[]) {
    Session session(HTTP20);
    session.setUrl("https://m.so.com");
    session.set_callback(callback);
    Response resp = session.get();
    qDebug() << resp.getHeader().getStatus();
}
