const {library, Method, make_ScReq_callback, read_to_string} = require("./bindings");
const {Response} = require("./Response")

const ALPN = Object.freeze({
    HTTP10: "http/1.0",
    HTTP11: "http/1.1",
    HTTP20: "h2"
})

const registry = new FinalizationRegistry(req => {
    library.ScReq_drop(req)
})

class Session {
    constructor(alpn, rand_tls, token, verify = true) {
        this.req = library.ScReq_new();
        if (alpn) {
            let ret = library.ScReq_set_alpn(this.req, alpn)
            if (ret === -1) throw "set_alpn error"
        }
        if (rand_tls && token) {
            let ret = library.ScReq_set_random_fingerprint(this.req, token);
            if (ret === -2) console.log("free user, set_random_fingerprint can't be used")
            if (ret === -1) throw "set_random_fingerprint error"
        }
        library.ScReq_set_verify(this.req, verify)
        registry.register(this, this.req)
    }

    set_fingerprint(fingerprint, token) {
        let ret = library.ScReq_set_fingerprint(this.req, fingerprint, token);
        if (ret === -2) console.log("free user, set_fingerprint can't be used")
        if (ret === -1) throw "set_fingerprint error"
    }

    set_ja3(ja3, token) {
        let ret = library.ScReq_set_ja3(this.req, ja3, token);
        if (ret === -2) console.log("free user, set_ja3 can't be used")
        if (ret === -1) throw "set_ja3 error"

    }

    set_ja4(ja4, token) {
        let ret = library.ScReq_set_ja4(this.req, ja4, token);
        if (ret === -2) console.log("free user, set_ja4 can't be used")
        if (ret === -1) throw "set_ja4 error"

    }

    set_headers(header) {
        let header_str = JSON.stringify(header);
        let ret = library.ScReq_set_header_json(this.req, header_str)
        if (ret === -1) throw "set_header_json error"
    }

    add_header(name, value) {
        let ret = library.ScReq_add_header(name, value)
        if (ret === -1) throw "add_header error"
    }

    set_proxy(proxy) {
        let ret = library.ScReq_set_proxy(this.req, proxy);
        if (ret === -1) throw "add_header error"
    }

    add_param(name, value) {
        let ret = library.ScReq_add_param(this.req, name, value);
        if (ret === -1) throw "add_param error"
    }

    /*
    Timeout{
        connect:3000,
        read:3000,
        write:3000,
        handle:30000,
        connect_times:3,
        handle_times:3
    }
     */
    set_timeout(timeout) {
        let timeout_str = JSON.stringify(timeout);
        let ret = library.ScReq_set_timeout(this.req, timeout_str);
        if (ret === -1) throw "set_timeout error"
    }

    set_cookie(cookie) {
        let ret = library.ScReq_set_cookie(this.req, cookie)
        if (ret === -1) throw "set_cookie error"
    }

    add_cookie(name, value) {
        let ret = library.ScReq_add_cookie(this.req, name, value)
        if (ret === -1) throw "add_cookie error"
    }

    reconnect() {
        let ret = library.ScReq_reconnect(this.req)
        if (ret === -1) throw "reconnect error"
    }

    set_callback(func) {
        let callback = make_ScReq_callback(func)
        library.ScReq_set_callback(this.req, callback)
    }

    _format_body(data, json, bytes, ct) {
        if (data !== null) {
            let keys = Object.keys(data)
            let res = "";
            for (let i = 0; i < keys.length; i++) {
                res += keys[i];
                res += "="
                res += encodeURIComponent(JSON.stringify(data[keys[i]]))
                res += "&"
            }
            if (res.endsWith("&")) {
                res = res.substring(0, res.length - 1)
            }
            if (ct === null)
                return [new TextEncoder().encode(res), "application/x-www-form-urlencoded"]
            else return [new TextEncoder().encode(res), ct]
        }
        if (json !== null) {
            let res = JSON.stringify(json);
            if (ct === null)
                return [new TextEncoder().encode(res), "application/json"]
            else return [new TextEncoder().encode(res), ct]
        }
        if (bytes !== null)
            if (ct === null)
                return [bytes, "application/octet-stream"]
            else return [bytes, ct]
        return [new TextEncoder().encode(""), "application/octet-stream"]
    }

    send(method, url, data, json, bytes, ct) {
        let body = this._format_body(data, json, bytes, ct)
        let resp = library.ScReq_stream_io(this.req, method, url, body[0], body[0].length, body[1])
        let buffer = Buffer.from(read_to_string(resp), "hex");
        let response = new Response(buffer);
        response.header.method = method;
        library.char_free(resp)//；这里需要手动释放吗
        return response;
    }

    get(url, data, json, bytes, ct) {
        return this.send(Method.GET, url, data, json, bytes, ct)
    }

    post(url, data, json, bytes, ct) {
        return this.send(Method.POST, url, data, json, bytes, ct)
    }

    options(url, data, json, bytes, ct) {
        return this.send(Method.OPTIONS, url, data, json, bytes, ct)
    }

    head(url, data, json, bytes, ct) {
        return this.send(Method.HEAD, url, data, json, bytes, ct)
    }

    trace(url, data, json, bytes, ct) {
        return this.send(Method.TRACE, url, data, json, bytes, ct)
    }

    delete(url, data, json, bytes, ct) {
        return this.send(Method.DELETE, url, data, json, bytes, ct)
    }

    patch(url, data, json, bytes, ct) {
        return this.send(Method.PATCH, url, data, json, bytes, ct)
    }

    close() {
        registry.unregister(this);
        library.ScReq_drop(this.req)
    }
}

module.exports = {
    Session, ALPN, Method, Response
}