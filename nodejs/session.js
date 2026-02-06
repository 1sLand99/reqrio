const {library} = require("./bindings");
const {Response} = require("./Response")

const ALPN = Object.freeze({
    HTTP10: "http/1.0",
    HTTP11: "http/1.1",
    HTTP20: "h2"
})

const Method = Object.freeze({
    GET: "GET",
    POST: "POST",
    OPTIONS: "OPTIONS",
    HEAD: "HEAD",
    DELETE: "DELETE",
    TRACH: "TRACH",

})

const registry = new FinalizationRegistry(req => {
    library.destroy(req)
})

class Session {
    constructor(alpn, rand_tls) {
        this.req = library.new_http();
        if (alpn) {
            let ret = library.set_alpn(this.req, alpn)
            if (ret === -1) throw "set_alpn error"
        }
        if (rand_tls) {
            let ret = library.set_random_fingerprint(this.req);
            if (ret === -2) throw "free user, set_random_fingerprint can't be used"
            if (ret === -1) throw "set_random_fingerprint error"
        }
        registry.register(this, this.req)
    }

    set_fingerprint(fingerprint) {
        let ret = library.set_fingerprint(this.req, fingerprint);
        if (ret === -2) throw "free user, set_fingerprint can't be used"
        if (ret === -1) throw "set_fingerprint error"
    }

    set_ja3(ja3) {
        let ret = library.set_ja3(this.req, ja3);
        if (ret === -2) throw "free user, set_ja3 can't be used"
        if (ret === -1) throw "set_ja3 error"

    }

    set_ja4(ja4) {
        let ret = library.set_ja4(this.req, ja4);
        if (ret === -2) throw "free user, set_ja4 can't be used"
        if (ret === -1) throw "set_ja4 error"

    }

    set_header_json(header) {
        let header_str = JSON.stringify(header);
        let ret = library.set_header_json(this.req, header_str)
        if (ret === -1) throw "set_header_json error"
    }

    add_header(name, value) {
        let ret = library.add_header(name, value)
        if (ret === -1) throw "add_header error"
    }

    set_proxy(proxy) {
        let ret = library.set_proxy(this.req, proxy);
        if (ret === -1) throw "add_header error"
    }


    set_url(url) {
        let ret = library.set_url(this.req, url)
        if (ret === -1) throw "set_url error"
    }

    add_param(name, value) {
        let ret = library.add_param(this.req, name, value);
        if (ret === -1) throw "add_param error"
    }

    set_data(data) {
        let data_str = JSON.stringify(data)
        let ret = library.set_data(data_str);
        if (ret === -1) throw "set_data error"
    }

    set_json(json) {
        let json_str = JSON.stringify(this.req, json);
        let ret = library.set_header_json(this.req, json_str);
        if (ret === -1) throw "set_json error"
    }

    set_bytes(buffer) {
        let ret = library.set_bytes(this.req, buffer, buffer.length);
        if (ret === -1) throw "set_bytes error"
    }

    set_text(text) {
        let ret = library.set_text(this.req, text);
        if (ret === -1) throw "set_text error"
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
        let ret = library.set_timeout(this.req, timeout_str);
        if (ret === -1) throw "set_timeout error"
    }

    set_cookie(cookie) {
        let ret = library.set_cookie(this.req, cookie)
        if (ret === -1) throw "set_cookie error"
    }

    add_cookie(name, value) {
        let ret = library.add_cookie(this.req, name, value)
        if (ret === -1) throw "add_cookie error"
    }

    reconnect() {
        let ret = library.reconnect(this.req)
        if (ret === -1) throw "reconnect error"
    }

    send(method) {
        let resp;
        switch (method) {
            case Method.GET:
                resp = library.get(this.req)
                break
            case Method.POST:
                resp = library.post(this.req)
                break
            case Method.OPTIONS:
                resp = library.options(this.req)
                break
            case Method.HEAD:
                resp = library.head(this.req)
                break
            case Method.DELETE:
                throw "unsupported method"
            case Method.TRACH:
                resp = library.trach(this.req)
                break
            default:
                throw "unsupported method :" + method
        }
        let response = new Response(Buffer.from(resp, "hex"));
        response.header.method = method;
        return response;


    }

    get() {
        return this.send(Method.GET)
    }

    post() {
        return this.send(Method.POST)
    }

    options() {
        return this.send(Method.OPTIONS)
    }

    head() {
        return this.send(Method.HEAD)
    }

    trach() {
        return this.send(Method.TRACH)
    }

    close() {
        registry.unregister(this);
        library.destroy(this.req)
    }
}

module.exports = {
    Session, ALPN, Method, Response
}