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
    constructor(alpn, rand_tls, token) {
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

    set_header_json(header) {
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


    set_url(url) {
        let ret = library.ScReq_set_url(this.req, url)
        if (ret === -1) throw "set_url error"
    }

    add_param(name, value) {
        let ret = library.ScReq_add_param(this.req, name, value);
        if (ret === -1) throw "add_param error"
    }

    set_data(data) {
        let data_str = JSON.stringify(data)
        let ret = library.ScReq_set_data(data_str);
        if (ret === -1) throw "set_data error"
    }

    set_json(json) {
        let json_str = JSON.stringify(this.req, json);
        let ret = library.ScReq_set_header_json(this.req, json_str);
        if (ret === -1) throw "set_json error"
    }

    set_bytes(buffer) {
        let ret = library.ScReq_set_bytes(this.req, buffer, buffer.length);
        if (ret === -1) throw "set_bytes error"
    }

    set_text(text) {
        let ret = library.ScReq_set_text(this.req, text);
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

    send(method) {
        let resp = library.ScReq_stream_io(this.req, Method.GET)
        let buffer = Buffer.from(read_to_string(resp), "hex");
        let response = new Response(buffer);
        response.header.method = method;
        library.char_free(resp)//；这里需要手动释放吗
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

    trace() {
        return this.send(Method.TRACE)
    }

    delete() {
        return this.send(Method.DELETE)
    }

    patch() {
        return this.send(Method.PATCH)
    }

    close() {
        registry.unregister(this);
        library.ScReq_drop(this.req)
    }
}

module.exports = {
    Session, ALPN, Method, Response
}