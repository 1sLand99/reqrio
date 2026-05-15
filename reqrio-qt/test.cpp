//
// Created by XLX on 2026/1/1.
//

#include <iostream>
#include <ostream>

#include "Session.h"
#include "WebSocket.h"

void callback(const char *data, uint32_t len) {
    QByteArray bytes = QByteArray::fromRawData(data, len);
    qDebug() << bytes.length();
}

int main(int argc, char *argv[]) {
    Session session(HTTP20);
    Response resp = session.get(new Url("https://m.so.com"), new Body());
    qDebug() << resp.statusCode();
    qDebug() << resp.text()<<resp.text().length();

    // try {
    //     WebSocket webSocket("wss://alive.github.com");
    //     webSocket.open();
    // } catch (std::exception &e) {
    //     qDebug() << e.what();
    // }

    // QJsonObject obj = webSocket.read();
}
