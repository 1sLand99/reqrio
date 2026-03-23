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
    Session session(HTTP20, true, "1", false);
    session.setUrl("https://m.so.com");
    session.setText("sdfsdf");
    session.setCallback(callback);
    Response resp = session.get();
    qDebug() << resp.getHeader().getStatus();

    try {
        WebSocket webSocket("wss://alive.github.com");
        webSocket.open();
    } catch (std::exception &e) {
        qDebug() << e.what();
    }

    // QJsonObject obj = webSocket.read();
}
