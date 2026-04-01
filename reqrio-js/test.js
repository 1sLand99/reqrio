const {Session, ALPN, Websocket} = require('./index')

let session = new Session(ALPN.HTTP20, true, "sd", false);
session.set_callback(function (data) {
    console.log(data.length)
})
let resp = session.get("https://m.so.com", null, null, new TextEncoder().encode("sdfdgdfg"), "text/plain");
console.log(resp.status_code())
console.log(resp.header)
session.close();


let ws = new Websocket();
ws.set_url("wss://alive.github.com")
ws.open()
ws.read()