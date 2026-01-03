//
// Created by XLX on 2026/1/1.
//

#ifndef REQRIO_RESPONSE_H
#define REQRIO_RESPONSE_H
#include <list>
#include <stdexcept>
#include <string>
#include <vector>

#include "bindings.h"
using namespace std;

class Cookie {
    string name;
    string value;
    int age = 0;
    string domain;
    string path;
    bool httpOnly = false;
    bool secure = false;
    string expires;
    string sameSite;
    bool icpsp = false;

public:
    explicit Cookie();

    explicit Cookie(string name, string value);

    string getName();

    string getValue();
};

class Header {
    string name;
    string value;
};

class Headers {
    Method method = GET;
    string agreement;
    string uri;
    int status = -1;
    list<Cookie> cookies;
    list<Header> keys;
};


class Response {
    Headers headers;
    char *body = nullptr;

private:
    static int hexChar(char c) {
        if ('0' <= c && c <= '9') return c - '0';
        if ('a' <= c && c <= 'f') return c - 'a' + 10;
        if ('A' <= c && c <= 'F') return c - 'A' + 10;
        throw std::invalid_argument("invalid hex char");
    }

    static vector<uint8_t> hexDecode(const std::string& hex) {
        if (hex.size() % 2 != 0)
            throw std::invalid_argument("hex length must be even");

        std::vector<uint8_t> out;
        out.reserve(hex.size() / 2);

        for (size_t i = 0; i < hex.size(); i += 2) {
            int high = hexChar(hex[i]);
            int low  = hexChar(hex[i + 1]);
            out.push_back(static_cast<uint8_t>((high << 4) | low));
        }
        return out;
    }

public:
    Response() = default;
    Response(string res);
    int length() const;

};


#endif //REQRIO_RESPONSE_H
