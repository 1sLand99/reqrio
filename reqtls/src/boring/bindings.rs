use std::os::raw::{c_char, c_int, c_uint, c_void};

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct EVP_AEAD {
    _unused: [u8; 0],
}

#[repr(C)]
#[derive(Copy, Clone)]
#[allow(non_camel_case_types)]
pub union evp_aead_ctx_st_state {
    pub opaque: [u8; 564usize],
    pub alignment: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct EVP_AEAD_CTX {
    pub aead: *const EVP_AEAD,
    pub state: evp_aead_ctx_st_state,
    pub tag_len: u8,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct ENGINE {
    _unused: [u8; 0],
}

pub const EVP_AEAD_DEFAULT_TAG_LENGTH: i32 = 0;

unsafe extern "C" {
    pub fn EVP_aead_aes_128_gcm() -> *const EVP_AEAD;

    pub fn EVP_aead_aes_256_gcm() -> *const EVP_AEAD;

    pub fn EVP_aead_chacha20_poly1305() -> *const EVP_AEAD;

    pub fn EVP_AEAD_CTX_cleanup(ctx: *mut EVP_AEAD_CTX);

    pub fn EVP_AEAD_CTX_init(
        ctx: *mut EVP_AEAD_CTX,
        aead: *const EVP_AEAD,
        key: *const u8,
        key_len: usize,
        tag_len: usize,
        impl_: *mut ENGINE,
    ) -> c_int;

    pub fn EVP_AEAD_CTX_seal(
        ctx: *const EVP_AEAD_CTX,
        out: *mut u8,
        out_len: *mut usize,
        max_out_len: usize,
        nonce: *const u8,
        nonce_len: usize,
        in_: *const u8,
        in_len: usize,
        ad: *const u8,
        ad_len: usize,
    ) -> c_int;

    pub fn EVP_AEAD_CTX_open(
        ctx: *const EVP_AEAD_CTX,
        out: *mut u8,
        out_len: *mut usize,
        max_out_len: usize,
        nonce: *const u8,
        nonce_len: usize,
        in_: *const u8,
        in_len: usize,
        ad: *const u8,
        ad_len: usize,
    ) -> c_int;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct EVP_CIPHER {
    _unused: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub struct EVP_CIPHER_CTX {
    pub cipher: *const EVP_CIPHER,
    pub app_data: *mut c_void,
    pub cipher_data: *mut c_void,
    pub key_len: c_uint,
    pub encrypt: c_int,
    pub flags: u32,
    pub oiv: [u8; 16usize],
    pub iv: [u8; 16usize],
    pub buf: [u8; 32usize],
    pub buf_len: c_int,
    pub num: c_uint,
    pub final_used: c_int,
    pub final_: [u8; 32usize],
    pub poisoned: c_int,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct EVP_MD {
    _unused: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub struct EVP_ENCODE_CTX {
    pub data_used: c_uint,
    pub data: [u8; 48usize],
    pub eof_seen: c_char,
    pub error_encountered: c_char,
}



unsafe extern "C" {
    pub fn EVP_aes_128_cbc() -> *const EVP_CIPHER;

    pub fn EVP_aes_192_cbc() -> *const EVP_CIPHER;

    pub fn EVP_aes_256_cbc() -> *const EVP_CIPHER;

    pub fn EVP_aes_128_ecb() -> *const EVP_CIPHER;

    pub fn EVP_aes_192_ecb() -> *const EVP_CIPHER;

    pub fn EVP_aes_256_ecb() -> *const EVP_CIPHER;

    pub fn EVP_aes_128_gcm() -> *const EVP_CIPHER;

    pub fn EVP_aes_192_gcm() -> *const EVP_CIPHER;

    pub fn EVP_aes_256_gcm() -> *const EVP_CIPHER;

    pub fn EVP_aes_128_ofb() -> *const EVP_CIPHER;

    pub fn EVP_aes_192_ofb() -> *const EVP_CIPHER;

    pub fn EVP_aes_256_ofb() -> *const EVP_CIPHER;

    pub fn EVP_aes_128_ctr() -> *const EVP_CIPHER;

    pub fn EVP_aes_192_ctr() -> *const EVP_CIPHER;

    pub fn EVP_aes_256_ctr() -> *const EVP_CIPHER;


    pub fn EVP_des_ecb() -> *const EVP_CIPHER;

    pub fn EVP_des_cbc() -> *const EVP_CIPHER;

   

    pub fn EVP_CIPHER_CTX_new() -> *mut EVP_CIPHER_CTX;

    pub fn EVP_CIPHER_CTX_free(ctx: *mut EVP_CIPHER_CTX);

    pub fn CRYPTO_memcmp(
        a: *const c_void,
        b: *const c_void,
        len: usize,
    ) -> c_int;

    pub fn EVP_EncryptInit_ex(
        ctx: *mut EVP_CIPHER_CTX,
        cipher: *const EVP_CIPHER,
        impl_: *mut ENGINE,
        key: *const u8,
        iv: *const u8,
    ) -> c_int;

    pub fn EVP_EncryptUpdate(
        ctx: *mut EVP_CIPHER_CTX,
        out: *mut u8,
        out_len: *mut c_int,
        in_: *const u8,
        in_len: c_int,
    ) -> c_int;

    pub fn EVP_EncryptFinal_ex(
        ctx: *mut EVP_CIPHER_CTX,
        out: *mut u8,
        out_len: *mut c_int,
    ) -> c_int;

    pub fn HMAC(
        evp_md: *const EVP_MD,
        key: *const c_void,
        key_len: usize,
        data: *const u8,
        data_len: usize,
        out: *mut u8,
        out_len: *mut c_uint,
    ) -> *mut u8;

    pub fn EVP_DecryptInit_ex(
        ctx: *mut EVP_CIPHER_CTX,
        cipher: *const EVP_CIPHER,
        impl_: *mut ENGINE,
        key: *const u8,
        iv: *const u8,
    ) -> c_int;

    pub fn EVP_DecryptUpdate(
        ctx: *mut EVP_CIPHER_CTX,
        out: *mut u8,
        out_len: *mut c_int,
        in_: *const u8,
        in_len: c_int,
    ) -> c_int;

    pub fn EVP_DecryptFinal_ex(
        ctx: *mut EVP_CIPHER_CTX,
        out: *mut u8,
        out_len: *mut c_int,
    ) -> c_int;

    pub fn EVP_CIPHER_CTX_set_padding(
        ctx: *mut EVP_CIPHER_CTX,
        pad: c_int,
    ) -> c_int;

    pub fn EVP_ENCODE_CTX_new() -> *mut EVP_ENCODE_CTX;

    pub fn EVP_ENCODE_CTX_free(ctx: *mut EVP_ENCODE_CTX);

    pub fn EVP_EncodeUpdate(
        ctx: *mut EVP_ENCODE_CTX,
        out: *mut u8,
        out_len: *mut c_int,
        in_: *const u8,
        in_len: usize,
    );

    pub fn EVP_EncodeFinal(
        ctx: *mut EVP_ENCODE_CTX,
        out: *mut u8,
        out_len: *mut c_int,
    );

    pub fn EVP_DecodeUpdate(
        ctx: *mut EVP_ENCODE_CTX,
        out: *mut u8,
        out_len: *mut c_int,
        in_: *const u8,
        in_len: usize,
    ) -> c_int;

    pub fn EVP_DecodeFinal(
        ctx: *mut EVP_ENCODE_CTX,
        out: *mut u8,
        out_len: *mut c_int,
    ) -> c_int;

   
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct EC_KEY {
    _unused: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct EC_POINT {
    _unused: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct EC_GROUP {
    _unused: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct BN_CTX {
    _unused: [u8; 0],
}
#[allow(non_upper_case_globals)]
pub const NID_X9_62_prime256v1: i32 = 415;
#[allow(non_upper_case_globals)]
pub const NID_secp384r1: i32 = 715;
#[allow(non_upper_case_globals)]
pub const NID_secp521r1: i32 = 716;

#[repr(transparent)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub struct point_conversion_form_t(pub c_int);

impl point_conversion_form_t {
    // pub const POINT_CONVERSION_COMPRESSED: point_conversion_form_t = point_conversion_form_t(2);
    pub const POINT_CONVERSION_UNCOMPRESSED: point_conversion_form_t = point_conversion_form_t(4);
    // pub const POINT_CONVERSION_HYBRID: point_conversion_form_t = point_conversion_form_t(6);
}

unsafe extern "C" {
    pub fn EC_KEY_new_by_curve_name(nid: c_int) -> *mut EC_KEY;

    pub fn EC_KEY_generate_key(key: *mut EC_KEY) -> c_int;

    pub fn EC_KEY_free(key: *mut EC_KEY);

    pub fn EC_KEY_get0_public_key(key: *const EC_KEY) -> *const EC_POINT;

    pub fn EC_KEY_get0_group(key: *const EC_KEY) -> *const EC_GROUP;

    pub fn EC_POINT_new(group: *const EC_GROUP) -> *mut EC_POINT;

    pub fn EC_POINT_free(point: *mut EC_POINT);

    pub fn EC_GROUP_get_degree(group: *const EC_GROUP) -> c_uint;

    pub fn OPENSSL_free(ptr: *mut c_void);

    pub fn EC_POINT_point2buf(
        group: *const EC_GROUP,
        point: *const EC_POINT,
        form: point_conversion_form_t,
        out_buf: *mut *mut u8,
        ctx: *mut BN_CTX,
    ) -> usize;

    pub fn EC_POINT_oct2point(
        group: *const EC_GROUP,
        point: *mut EC_POINT,
        buf: *const u8,
        len: usize,
        ctx: *mut BN_CTX,
    ) -> c_int;

    pub fn ECDH_compute_key(
        out: *mut c_void,
        outlen: usize,
        pub_key: *const EC_POINT,
        priv_key: *const EC_KEY,
        kdf: Option<
            unsafe extern "C" fn(
                in_: *const c_void,
                inlen: usize,
                out: *mut c_void,
                outlen: *mut usize,
            ) -> *mut c_void,
        >,
    ) -> c_int;

}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct EVP_PKEY {
    _unused: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct EVP_PKEY_CTX {
    _unused: [u8; 0],
}

pub const EVP_PKEY_X25519: i32 = 948;

unsafe extern "C" {
    pub fn EVP_PKEY_new() -> *mut EVP_PKEY;
    pub fn EVP_PKEY_CTX_new_id(id: c_int, e: *mut ENGINE) -> *mut EVP_PKEY_CTX;

    pub fn EVP_PKEY_keygen_init(ctx: *mut EVP_PKEY_CTX) -> c_int;

    pub fn EVP_PKEY_CTX_free(ctx: *mut EVP_PKEY_CTX);

    pub fn EVP_PKEY_CTX_new(pkey: *mut EVP_PKEY, e: *mut ENGINE) -> *mut EVP_PKEY_CTX;

    pub fn EVP_PKEY_free(pkey: *mut EVP_PKEY);

    pub fn EVP_PKEY_derive_init(ctx: *mut EVP_PKEY_CTX) -> c_int;

    pub fn EVP_PKEY_keygen(
        ctx: *mut EVP_PKEY_CTX,
        out_pkey: *mut *mut EVP_PKEY,
    ) -> c_int;

    pub fn EVP_PKEY_derive_set_peer(
        ctx: *mut EVP_PKEY_CTX,
        peer: *mut EVP_PKEY,
    ) -> c_int;

    pub fn EVP_PKEY_get_raw_public_key(
        pkey: *const EVP_PKEY,
        out: *mut u8,
        out_len: *mut usize,
    ) -> c_int;

    pub fn EVP_PKEY_derive(
        ctx: *mut EVP_PKEY_CTX,
        key: *mut u8,
        out_key_len: *mut usize,
    ) -> c_int;

    pub fn EVP_PKEY_new_raw_public_key(
        type_: c_int,
        unused: *mut ENGINE,
        in_: *const u8,
        len: usize,
    ) -> *mut EVP_PKEY;
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub struct HMAC_CTX {
    pub md: *const EVP_MD,
    pub md_ctx: EVP_MD_CTX,
    pub i_ctx: EVP_MD_CTX,
    pub o_ctx: EVP_MD_CTX,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub struct EVP_MD_CTX {
    pub digest: *const EVP_MD,
    pub md_data: *mut c_void,
    pub pctx: *mut EVP_PKEY_CTX,
    pub pctx_ops: *const evp_md_pctx_ops,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct evp_md_pctx_ops {
    _unused: [u8; 0],
}


unsafe extern "C"{
    pub fn EVP_md5() -> *const EVP_MD;
    pub fn EVP_sha1() -> *const EVP_MD;

    pub fn EVP_sha256() -> *const EVP_MD;

    pub fn EVP_sha384() -> *const EVP_MD;

    pub fn EVP_sha512() -> *const EVP_MD;

    pub fn HMAC_CTX_new() -> *mut HMAC_CTX;

    pub fn HMAC_CTX_free(ctx: *mut HMAC_CTX);

    pub fn EVP_MD_CTX_new() -> *mut EVP_MD_CTX;

    pub fn EVP_MD_CTX_free(ctx: *mut EVP_MD_CTX);

    pub fn EVP_MD_CTX_copy_ex(
        out: *mut EVP_MD_CTX,
        in_: *const EVP_MD_CTX,
    ) -> c_int;

    pub fn HMAC_Init_ex(
        ctx: *mut HMAC_CTX,
        key: *const c_void,
        key_len: usize,
        md: *const EVP_MD,
        impl_: *mut ENGINE,
    ) -> c_int;

    pub fn HMAC_Update(
        ctx: *mut HMAC_CTX,
        data: *const u8,
        data_len: usize,
    ) -> c_int;

    pub fn HMAC_Final(
        ctx: *mut HMAC_CTX,
        out: *mut u8,
        out_len: *mut c_uint,
    ) -> c_int;

    pub fn EVP_DigestInit_ex(
        ctx: *mut EVP_MD_CTX,
        type_: *const EVP_MD,
        engine: *mut ENGINE,
    ) -> c_int;

    pub fn EVP_DigestUpdate(
        ctx: *mut EVP_MD_CTX,
        data: *const c_void,
        len: usize,
    ) -> c_int;

    pub fn EVP_DigestFinal_ex(
        ctx: *mut EVP_MD_CTX,
        md_out: *mut u8,
        out_size: *mut c_uint,
    ) -> c_int;

    pub fn EVP_Digest(
        data: *const c_void,
        len: usize,
        md_out: *mut u8,
        md_out_size: *mut c_uint,
        type_: *const EVP_MD,
        impl_: *mut ENGINE,
    ) -> c_int;
}