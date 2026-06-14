const {ja4, post_form, post_json, get, client_hello, ja3, custom_fingerprint} = require("./example");

async function test_ws() {
    try {
        let ws = new Websocket();
        ws.open_raw("wss://echo.websocket.org", "");
        let frame = ws.read();
        console.log("WS frame:", frame);
        ws.close();
    } catch (e) {
        console.error("WS error:", e.message);
    }
}


get();
post_form();
// post_json();
// ja3();
// ja4();
// client_hello();
// custom_fingerprint()

/*
#
# Fatal error in , line 0
# Check failed: result.second.
#
#
#
#FailureMessage Object: 0x7ffd5639da40
 1: 0x7f27eb18ab89  [/lib64/libnode.so.93]
 2: 0x7f27ebf0787d V8_Fatal(char const*, ...) [/lib64/libnode.so.93]
 3: 0x7f27eb9dd4a2 v8::internal::GlobalBackingStoreRegistry::Register(std::shared_ptr<v8::internal::BackingStore>) [/lib64/libnode.so.93]
 4: 0x7f27eb74c4a4 v8::ArrayBuffer::GetBackingStore() [/lib64/libnode.so.93]
 5: 0x7f27eb0bc6c0 napi_get_typedarray_info [/lib64/libnode.so.93]
 6: 0x7f27e4c07d50  [/home/xl/project/rust/reqrio/node_modules/ref-napi/prebuilds/linux-x64/node.napi.node]
 7: 0x7f27ea2771dd FFI::FFI::FFICall(Napi::CallbackInfo const&) [/home/xl/project/rust/reqrio/node_modules/ffi-napi/build/Release/ffi_bindings.node]
 8: 0x7f27ea27a0e5 Napi::details::CallbackData<void (*)(Napi::CallbackInfo const&), void>::Wrapper(napi_env__*, napi_callback_info__*) [/home/xl/project/rust/reqrio/node_modules/ffi-napi/build/Release/ffi_bindings.node]
 9: 0x7f27eb0b0f7e  [/lib64/libnode.so.93]
10: 0x7f27eb77a378 v8::internal::FunctionCallbackArguments::Call(v8::internal::CallHandlerInfo) [/lib64/libnode.so.93]
11: 0x7f27eb77aa81  [/lib64/libnode.so.93]
12: 0x7f27eb77aeed v8::internal::Builtin_HandleApiCall(int, unsigned long*, v8::internal::Isolate*) [/lib64/libnode.so.93]
13: 0x7f27eb378f99  [/lib64/libnode.so.93]

 */