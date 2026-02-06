const ffi = require('ffi-napi');
const ref = require('ref-napi');

const voidPtr = ref.refType(ref.types.void);
const charPtr = ref.types.CString;
const bytePtr = ref.refType(ref.types.char)

const library = ffi.Library("./libreqrio.so", {
    new_http: [voidPtr, []],
    set_header_json: ['int', [voidPtr, charPtr]],
    // set_random_fingerprint: ["int", [voidPtr]],
    add_header: ["int", [voidPtr, charPtr, charPtr]],
    set_alpn: ["int", [voidPtr, charPtr]],
    // set_fingerprint: ["int", [voidPtr, charPtr]],
    // set_ja3: ["int", [voidPtr, charPtr]],
    // set_ja4: ['int', [voidPtr, charPtr]],
    set_proxy: ['int', [voidPtr, charPtr]],
    set_url: ['int', [voidPtr, charPtr]],
    add_param: ['int', [voidPtr, charPtr, charPtr]],
    set_data: ['int', [voidPtr, charPtr]],
    set_json: ['int', [voidPtr, charPtr]],
    set_bytes: ['int', [voidPtr, bytePtr, "uint32"]],
    set_text: ["int", [voidPtr, charPtr]],
    set_timeout: ["int", [voidPtr, charPtr]],
    set_cookie: ['int', [voidPtr, charPtr]],
    add_cookie: ['int', [voidPtr, charPtr, charPtr]],
    reconnect: ['int', [voidPtr]],
    get: [charPtr, [voidPtr]],
    post: [charPtr, [voidPtr]],
    options: [charPtr, [voidPtr]],
    head: [charPtr, [voidPtr]],
    // delete_: [charPtr, [voidPtr]],
    trach: [charPtr, [voidPtr]],
    destroy: ['int', [voidPtr]],
    free_pointer: ['int', [charPtr]],
})

module.exports={library}
