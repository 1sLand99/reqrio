const {library, check_error, ref_char_ptr} = require('./bindings')

class Url {

    /**初始化Url
     * @param {string} base_url
     * @param {object|null} params
     * @param {string|null} sni
     **/
    constructor(base_url, params = null, sni = null) {
        const errPtr = ref_char_ptr();
        this.ptr = library.Url_new(base_url, errPtr);
        check_error(errPtr.deref());
        if (params !== undefined && params !== null) {
            for (const [key, value] of Object.entries(params)) {
                this.add_param(key, JSON.stringify(value));
            }
        }
        if (sni !== undefined && sni !== null) {
            this.set_sni(sni)
        }
    }

    /**添加一个查询参数
     * @param {string} name
     * @param {string} value
     **/
    add_param(name, value) {
        const err = library.Url_add_param(this.ptr, name, value);
        check_error(err, this.close);
    }

    /**移除一个查询参数
     * @param {string} name
     **/
    remove_param(name) {
        const err = library.Url_remove_param(this.ptr, name);
        check_error(err, this.close);
    }

    /**为该url设置SNI，在使用ip地址URL时使用
     * @param {string} sni
     **/
    set_sni(sni) {
        const err = library.Url_set_sni(this.ptr, sni);
        check_error(err, this.close);
    }

    close() {
        if (this.ptr == null) return;
        library.Url_drop(this.ptr);
        this.ptr = null;
    }
}

module.exports = {Url}

