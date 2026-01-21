//
// Created by XLX on 2026/1/1.
//

#include <iostream>
#include <ostream>

#include "Session.h"

int main(int argc, char *argv[]) {
    Session session(HTTP11);
    session.setUrl("https://www.baidu.com");
    Response resp = session.get();
    qDebug()<<resp.toString();
}
