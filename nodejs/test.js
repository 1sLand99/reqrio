const {Session, ALPN} = require('./session')


let session = new Session(ALPN.HTTP20);
session.set_url("https://m.so.com");
let resp = session.get();
console.log(resp.status_code())
console.log(resp.header)
session.close();