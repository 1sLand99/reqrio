class Header {
    constructor(json) {
        if (!json) return
        this.uri = json.uri;
        this.method = json.method;
        this.status = json.status;
        this.agreement = json.agreement;
        this.keys = json.keys
        this.cookies = []

        if (this.keys["Set-Cookie"]) {
            for (let i = 0; i < this.keys["Set-Cookie"].length; i++) {
                this.cookies.push(this.keys["Set-Cookie"][i])
            }
            delete this.keys["Set-Cookie"]
        }
        if (this.keys["set-cookie"]) {
            for (let i = 0; i < this.keys["set-cookie"].length; i++) {
                this.cookies.push(this.keys["set-cookie"][i])
            }
            delete this.keys["set-cookie"]
        }


    }
}


class Response {
    constructor(bytes) {
        let resp_text = bytes.toString('utf8')
        try {
            let resp_json = JSON.parse(resp_text);
            this.header = new Header(resp_json.header);
            this.body = Buffer.from(resp_json.body, 'hex')
        } catch (e) {
            throw resp_text
        }
    }

    status_code() {
        return this.header.status
    }

    text() {
        return this.body.toString('utf8')
    }
}


module.exports = {
    Response, Header
}