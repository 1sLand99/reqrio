const ffi = require('ffi-napi');
const ref = require('ref-napi');
const path = require("path");

const voidPtr = ref.refType(ref.types.void);
const charPtr = ref.types.CString;
const uint8Ptr = ref.refType(ref.types.uint8);

const Method = {
    GET: 0,
    POST: 1,
    PUT: 2,
    HEAD: 3,
    DELETE: 4,
    OPTIONS: 5,
    TRACE: 6,
    CONNECT: 7,
    PATCH: 8
}
let libname;
if (process.platform === "win32") {
    libname = "reqrio"
} else if (process.platform === "linux") {
    libname = "libreqrio"
} else {
    throw "unsupported system platform"
}
let libpath = path.join(__dirname, libname)
const library = ffi.Library(libpath, {
    ScReq_new: [voidPtr, []],
    ScReq_set_header_json: ['int', [voidPtr, charPtr]],
    ScReq_add_header: ["int", [voidPtr, charPtr, charPtr]],
    ScReq_set_alpn: ["int", [voidPtr, charPtr]],
    ScReq_set_verify: ["int", [voidPtr, 'bool']],
    ScReq_set_random_fingerprint: ["int", [voidPtr, charPtr]],
    ScReq_set_fingerprint: ["int", [voidPtr, charPtr, charPtr]],
    ScReq_set_ja3: ["int", [voidPtr, charPtr, charPtr]],
    ScReq_set_ja4: ['int', [voidPtr, charPtr, charPtr]],
    ScReq_set_proxy: ['int', [voidPtr, charPtr]],
    ScReq_set_url: ['int', [voidPtr, charPtr]],
    ScReq_add_param: ['int', [voidPtr, charPtr, charPtr]],
    ScReq_set_bytes: ['int', [voidPtr, uint8Ptr, "uint32", charPtr]],
    ScReq_set_context_type: ['int', [voidPtr, charPtr]],
    ScReq_set_timeout: ["int", [voidPtr, charPtr]],
    ScReq_set_cookie: ['int', [voidPtr, charPtr]],
    ScReq_add_cookie: ['int', [voidPtr, charPtr, charPtr]],
    ScReq_set_callback: ["int", [voidPtr, "pointer"]],
    ScReq_reconnect: ['int', [voidPtr]],
    ScReq_stream_io: ["pointer", [voidPtr, "int"]],
    ScReq_drop: ['int', [voidPtr]],
    char_free: ['int', [charPtr]],
    ws_build: [voidPtr, []],
    ws_add_header: ['int', [voidPtr, charPtr, charPtr]],
    ws_set_proxy: ['int', [voidPtr, charPtr]],
    ws_set_url: ['int', [voidPtr, charPtr]],
    ws_set_uri: ['int', [voidPtr, charPtr]],
    ws_open: [voidPtr, [voidPtr]],
    ws_open_raw: [voidPtr, [charPtr, charPtr]],
    ws_read: ['pointer', [voidPtr]],
    ws_write: ['int', [voidPtr, 'int', 'bool', charPtr]],
    ws_close: ['int', [voidPtr]]

})

function make_ScReq_callback(func) {
    return ffi.Callback("void", ["pointer", "uint32"], function (ptr, len) {
        const buffer = ref.reinterpret(ptr, len);
        const data = Buffer.from(buffer);
        func(data)
    })
}

function read_to_string(ptr) {
    return ref.readCString(ptr, 0)
}

module.exports = {
    library,
    Method,
    make_ScReq_callback,
    read_to_string
}
