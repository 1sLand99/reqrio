const {library, check_error, ref_char_ptr} = require('./bindings');

class Body {
    /**添加一个查询参数
     * @param {Uint8Array} data
     * @param {string} content_type
     **/
    static new(data, content_type) {
        const errPtr = ref_char_ptr();
        const bodyPtr = library.Body_new(data, data.length, content_type, errPtr);
        check_error(errPtr.deref())
        return bodyPtr;
    }


    static new_text(text) {
        const data = new TextEncoder().encode(text);
        return Body.new(data, 'text/plain')
    }

    /**创建form请求体
     * @param {object} form
     * @param {string} ct 类型
     **/
    static new_form(form, ct = "application/x-www-form-urlencoded") {
        let keys = Object.keys(form);
        let res = "";
        for (let i = 0; i < keys.length; i++) {
            res += keys[i];
            res += "=";
            res += encodeURIComponent(JSON.stringify(form[keys[i]]));
            res += "&";
        }
        if (res.endsWith("&")) {
            res = res.substring(0, res.length - 1);
        }
        return Body.new(new TextEncoder().encode(res), ct)
    }

    /**创建json请求体
     * @param {object} json
     * @param {string} ct 类型
     **/
    static new_json(json, ct = 'application/json') {
        const data = new TextEncoder().encode(JSON.stringify(json));
        return Body.new(data, ct)
    }

    static none() {
        return library.Body_none();
    }

    /**创建multi form请求体
     * @param {array} files 文件
     * @param {object} data
     **/
    static new_files(files, data = null) {
        const http_file = library.HttpFile_new();
        for (const file of files) {
            let errPtr = ref_char_ptr();
            const form = library.FileForm_new(file["path"], file["field_name"], file["filetype"]);
            try {
                check_error(errPtr.deref())
                check_error(library.HttpFile_add_form(http_file, form))
            } catch (e) {
                library.HttpFile_drop(file)
            }
        }
        let dataPtr = null;
        if (data !== null && data !== undefined) dataPtr = JSON.stringify(dataPtr)

        const errPtr = ref_char_ptr();
        const bodyPtr = library.Body_new_files(http_file, dataPtr, errPtr);
        check_error(errPtr);
        return bodyPtr;
    }

    static close(bodyPtr) {
        if (bodyPtr && !bodyPtr.isNull()) {
            library.Body_drop(bodyPtr);
        }
    }
}

module.exports = {Body}