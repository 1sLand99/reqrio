const ref = require("ref-napi");

class Fingerprint {
    constructor(library, token) {
        this.library = library;
        this.ptr = this.library.Fingerprint_new(token);
    }

    add_cipher_suite(suite) {
        this.library.Fingerprint_add_cipher_suite(this.ptr, suite);
    }

    add_extension(ext_type) {
        this.library.Fingerprint_add_ext(this.ptr, ext_type);
    }

    add_extension_alps(ext_type, alpn_list) {
        const buffers = alpn_list.map(s => Buffer.from(s + "\0"));
        const pointerSize = ref.sizeof.pointer;
        const ptrArray = Buffer.alloc(buffers.length * pointerSize);
        for (let i = 0; i < buffers.length; i++) {
            ptrArray.writePointer(buffers[i], i * pointerSize);
        }
        this.library.Fingerprint_add_ext_alps(this.ptr, ext_type, ptrArray, buffers.length);
    }

    /**
     * @param {number} ext_type
     * @param {array} versions
     */
    add_extension_versions(ext_type, versions) {
        const versions_u16 = Uint16Array.from(versions);
        this.library.Fingerprint_add_ext_version(this.ptr, ext_type, versions_u16, versions_u16.length);
    }

    /**
     * @param {number} ext_type
     * @param {array} curves
     */
    add_extension_curves(ext_type, curves) {
        const curves_u16 = Uint16Array.from(curves);
        this.library.Fingerprint_add_ext_curve(this.ptr, ext_type, curves_u16, curves_u16.length);
    }

    /**
     * @param {number} ext_type
     * @param {Uint16Array} methods
     */
    add_extension_compress(ext_type, methods) {
        this.library.Fingerprint_add_ext_compress(this.ptr, ext_type, methods, methods.length);
    }

    add_extension_psk_mode(ext_type, mode) {
        this.library.Fingerprint_add_ext_psk_mode(this.ptr, ext_type, mode);
    }

    /**
     * @param {number} ext_type
     * @param {number} padding
     */
    add_extension_padding(ext_type, padding) {
        this.library.Fingerprint_add_ext_padding(this.ptr, ext_type, padding);
    }

    /**
     * @param {number} ext_type
     * @param {array} bytes
     */
    add_extension_bytes(ext_type, bytes) {
        const bytes_u8 = Uint8Array.from(bytes)
        this.library.Fingerprint_add_ext_bytes(this.ptr, ext_type, bytes_u8, bytes_u8.length);
    }

    /**
     * @param {number} ext_type
     * @param {array} algorithms
     */
    add_extension_algorithms(ext_type, algorithms) {
        const algorithms_u16 = Uint16Array.from(algorithms);
        this.library.Fingerprint_add_ext_algorithm(this.ptr, ext_type, algorithms_u16, algorithms_u16.length);
    }

    /**
     * @param {number} ext_type
     * @param {array} points
     */
    add_extension_ec_point(ext_type, points) {
        const point_u8 = Uint8Array.from(points);
        this.library.Fingerprint_add_ext_ec_point(this.ptr, ext_type, point_u8, point_u8.length);
    }

    add_h2_setting(flag, value) {
        this.library.Fingerprint_add_h2_setting(this.ptr, flag, value);
    }

    set_h2_window_size(size) {
        this.library.Fingerprint_set_h2_window_size(this.ptr, size);
    }

    /**
     * @param {boolean} priority
     * @param {number} weight
     */
    set_h2_priority(priority, weight) {
        this.library.Fingerprint_set_h2_priority(this.ptr, priority, weight);
    }

    close() {
        if (this.ptr === null) return
        this.library.Fingerprint_drop(this.ptr);
        this.ptr = null;
    }
}

module.exports = {Fingerprint}