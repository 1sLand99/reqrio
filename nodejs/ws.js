const {library, read_to_string} = require("./bindings");
const registry = new FinalizationRegistry(ws => {
    library.ws_close(ws)
})

class Websocket {
    constructor() {
        this.build = library.ws_build();
        this.ws = null;
    }

    add_header(name, value) {
        let ret = library.ws_add_header(this.build, name, value)
        if (ret === -1) throw "add header error"
    }

    set_proxy(proxy) {
        let ret = library.ws_set_proxy(this.build, proxy);
        if (ret === -1) throw "set proxy error"
    }

    set_url(url) {
        let ret = library.ws_set_url(this.build, url)
        if (ret === -1) throw "set url error"
    }

    set_uri(uri) {
        let ret = library.ws_set_uri(this.build, uri)
        if (ret === -1) throw "set uri error"
    }

    open(url) {
        if (url) this.set_url(url)
        this.ws = library.ws_open(this.build)
        registry.register(this, this.ws)
    }

    read() {
        let ptr = library.ws_read(this.ws)
        let s = read_to_string(ptr)
        library.char_free(ptr)
        return JSON.parse(s)
    }

    write(opcode, mask, msg) {
        let ret = library.ws_write(this.ws, opcode, mask, msg)
        if (ret === -1) throw "ws write error"
    }

    close() {
        registry.unregister(this);
    }
}


module.exports = {
    Websocket
}