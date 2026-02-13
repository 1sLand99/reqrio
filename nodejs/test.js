const {Session, ALPN, Websocket} = require('./index')

let session = new Session(ALPN.HTTP20, false);
session.set_url("https://m.so.com");
session.set_callback(function (data) {
    console.log(data.length)
})
let resp = session.get();
console.log(resp.status_code())
console.log(resp.header)
session.close();


let ws = new Websocket();
ws.set_url("https://alive.github.com")
ws.open()
ws.read()