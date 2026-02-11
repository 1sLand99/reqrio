use std::os::raw::{c_char, c_int, c_long, c_uchar, c_uint, c_void};
use crate::boring::bindings::{EVP_CIPHER, EVP_PKEY, EVP_PKEY_CTX};

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub struct openssl_method_common_st {
    pub references: c_int,
    pub is_static: c_char,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct RSA_METHOD {
    pub common: openssl_method_common_st,
    pub app_data: *mut c_void,
    pub init: Option<unsafe extern "C" fn(rsa: *mut RSA) -> c_int>,
    pub finish: Option<unsafe extern "C" fn(rsa: *mut RSA) -> c_int>,
    pub size: Option<unsafe extern "C" fn(rsa: *const RSA) -> usize>,
    pub sign: Option<
        unsafe extern "C" fn(
            type_: c_int,
            m: *const u8,
            m_length: c_uint,
            sigret: *mut u8,
            siglen: *mut c_uint,
            rsa: *const RSA,
        ) -> c_int,
    >,
    pub sign_raw: Option<
        unsafe extern "C" fn(
            rsa: *mut RSA,
            out_len: *mut usize,
            out: *mut u8,
            max_out: usize,
            in_: *const u8,
            in_len: usize,
            padding: c_int,
        ) -> c_int,
    >,
    pub decrypt: Option<
        unsafe extern "C" fn(
            rsa: *mut RSA,
            out_len: *mut usize,
            out: *mut u8,
            max_out: usize,
            in_: *const u8,
            in_len: usize,
            padding: c_int,
        ) -> c_int,
    >,
    pub private_transform: Option<
        unsafe extern "C" fn(
            rsa: *mut RSA,
            out: *mut u8,
            in_: *const u8,
            len: usize,
        ) -> c_int,
    >,
    pub flags: c_int,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct stack_st_void {
    _unused: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub struct CRYPTO_EX_DATA {
    pub sk: *mut stack_st_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
#[allow(non_camel_case_types)]
pub union CRYPTO_MUTEX {
    pub handle: *mut c_void,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[allow(non_camel_case_types, non_snake_case)]
pub struct BN_MONT_CTX {
    pub RR: BIGNUM,
    pub N: BIGNUM,
    pub n0: [u64; 2usize],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct BN_BLINDING {
    _unused: [u8; 0],
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct __BindgenBitfieldUnit<Storage> {
    storage: Storage,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct RSA {
    pub meth: *mut RSA_METHOD,
    pub n: *mut BIGNUM,
    pub e: *mut BIGNUM,
    pub d: *mut BIGNUM,
    pub p: *mut BIGNUM,
    pub q: *mut BIGNUM,
    pub dmp1: *mut BIGNUM,
    pub dmq1: *mut BIGNUM,
    pub iqmp: *mut BIGNUM,
    pub ex_data: CRYPTO_EX_DATA,
    pub references: u32,
    pub flags: c_int,
    pub lock: CRYPTO_MUTEX,
    pub mont_n: *mut BN_MONT_CTX,
    pub mont_p: *mut BN_MONT_CTX,
    pub mont_q: *mut BN_MONT_CTX,
    pub d_fixed: *mut BIGNUM,
    pub dmp1_fixed: *mut BIGNUM,
    pub dmq1_fixed: *mut BIGNUM,
    pub inv_small_mod_large_mont: *mut BIGNUM,
    pub num_blindings: usize,
    pub blindings: *mut *mut BN_BLINDING,
    pub blindings_inuse: *mut c_uchar,
    pub blinding_fork_generation: u64,
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 1usize]>,
    pub __bindgen_padding_0: [u8; 7usize],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BIGNUM {
    pub d: *mut u64,
    pub width: c_int,
    pub dmax: c_int,
    pub neg: c_int,
    pub flags: c_int,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct BN_GENCB {
    pub arg: *mut c_void,
    pub callback: Option<
        unsafe extern "C" fn(
            event: c_int,
            n: c_int,
            arg1: *mut BN_GENCB,
        ) -> c_int,
    >,
}

#[allow(non_camel_case_types)]
pub type bio_info_cb = Option<
    unsafe extern "C" fn(
        bio: *mut BIO,
        event: c_int,
        parg: *const c_char,
        cmd: c_int,
        larg: c_long,
        return_value: c_long,
    ) -> c_long,
>;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct BIO_METHOD {
    pub type_: c_int,
    pub name: *const c_char,
    pub bwrite: Option<
        unsafe extern "C" fn(
            arg1: *mut BIO,
            arg2: *const c_char,
            arg3: c_int,
        ) -> c_int,
    >,
    pub bread: Option<
        unsafe extern "C" fn(
            arg1: *mut BIO,
            arg2: *mut c_char,
            arg3: c_int,
        ) -> c_int,
    >,
    pub bputs: Option<
        unsafe extern "C" fn(
            arg1: *mut BIO,
            arg2: *const c_char,
        ) -> c_int,
    >,
    pub bgets: Option<
        unsafe extern "C" fn(
            arg1: *mut BIO,
            arg2: *mut c_char,
            arg3: c_int,
        ) -> c_int,
    >,
    pub ctrl: Option<
        unsafe extern "C" fn(
            arg1: *mut BIO,
            arg2: c_int,
            arg3: c_long,
            arg4: *mut c_void,
        ) -> c_long,
    >,
    pub create:
        Option<unsafe extern "C" fn(arg1: *mut BIO) -> c_int>,
    pub destroy:
        Option<unsafe extern "C" fn(arg1: *mut BIO) -> c_int>,
    pub callback_ctrl: Option<
        unsafe extern "C" fn(
            arg1: *mut BIO,
            arg2: c_int,
            arg3: bio_info_cb,
        ) -> c_long,
    >,
}

#[allow(non_camel_case_types)]
pub type pem_password_cb = Option<
    unsafe extern "C" fn(
        buf: *mut c_char,
        size: c_int,
        rwflag: c_int,
        userdata: *mut c_void,
    ) -> c_int,
>;

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BIO {
    pub method: *const BIO_METHOD,
    pub init: c_int,
    pub shutdown: c_int,
    pub flags: c_int,
    pub retry_reason: c_int,
    pub num: c_int,
    pub references: u32,
    pub ptr: *mut c_void,
    pub next_bio: *mut BIO,
    pub num_read: usize,
    pub num_write: usize,
}

pub const RSA_F4: i32 = 65537;
pub const RSA_PKCS1_OAEP_PADDING: i32 = 4;


#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct X509 {
    _unused: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct STACK {
    pub num: usize,
    pub data: *mut *mut c_void,
    pub sorted: c_int,
    pub num_alloc: usize,
    pub comp: Option<
        unsafe extern "C" fn(
            a: *const *const c_void,
            b: *const *const c_void,
        ) -> c_int,
    >,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct X509_STORE {
    _unused: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct X509_STORE_CTX {
    _unused: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct stack_st_X509 {
    _unused: [u8; 0],
}


unsafe extern "C" {
    pub fn RSA_new() -> *mut RSA;

    pub fn RSA_free(rsa: *mut RSA);

    pub fn BN_new() -> *mut BIGNUM;

    pub fn BN_free(bn: *mut BIGNUM);

    pub fn BIO_new(method: *const BIO_METHOD) -> *mut BIO;

    pub fn BIO_new_mem_buf(buf: *const c_void, len: isize) -> *mut BIO;

    pub fn BIO_free(bio: *mut BIO) -> c_int;

    pub fn BIO_s_mem() -> *const BIO_METHOD;

    pub fn BN_set_word(bn: *mut BIGNUM, value: u64) -> c_int;

    pub fn EVP_PKEY_assign_RSA(pkey: *mut EVP_PKEY, key: *mut RSA) -> c_int;

    pub fn BIO_get_mem_data(bio: *mut BIO, contents: *mut *mut c_char) -> c_long;

    pub fn PEM_write_bio_PUBKEY(bp: *mut BIO, x: *mut EVP_PKEY) -> c_int;

    pub fn i2d_PrivateKey(key: *const EVP_PKEY, outp: *mut *mut u8) -> c_int;

    pub fn i2d_PUBKEY(pkey: *const EVP_PKEY, outp: *mut *mut u8) -> c_int;

    pub fn EVP_PKEY_encrypt_init(ctx: *mut EVP_PKEY_CTX) -> c_int;

    pub fn EVP_PKEY_decrypt_init(ctx: *mut EVP_PKEY_CTX) -> c_int;

    pub fn X509_get_pubkey(x509: *mut X509) -> *mut EVP_PKEY;

    pub fn X509_free(x509: *mut X509);

    pub fn i2d_X509(x509: *mut X509, outp: *mut *mut u8) -> c_int;

    pub fn sk_new_null() -> *mut STACK;

    pub fn sk_push(sk: *mut STACK, p: *mut c_void) -> usize;

    pub fn sk_free(sk: *mut STACK);

    pub fn X509_STORE_new() -> *mut X509_STORE;

    pub fn X509_STORE_add_cert(ctx: *mut X509_STORE, x: *mut X509) -> c_int;

    pub fn X509_STORE_free(v: *mut X509_STORE);

    pub fn X509_STORE_CTX_new() -> *mut X509_STORE_CTX;

    pub fn X509_STORE_CTX_free(ctx: *mut X509_STORE_CTX);

    pub fn X509_verify_cert(ctx: *mut X509_STORE_CTX) -> c_int;

    pub fn X509_STORE_CTX_get_error(ctx: *mut X509_STORE_CTX) -> c_int;

    pub fn X509_verify_cert_error_string(err: c_long) -> *const c_char;

    pub fn RSA_generate_key_ex(
        rsa: *mut RSA,
        bits: c_int,
        e: *const BIGNUM,
        cb: *mut BN_GENCB,
    ) -> c_int;

    pub fn PEM_write_bio_PrivateKey(
        bp: *mut BIO,
        x: *mut EVP_PKEY,
        enc: *const EVP_CIPHER,
        kstr: *mut c_uchar,
        klen: c_int,
        cb: pem_password_cb,
        u: *mut c_void,
    ) -> c_int;

    pub fn EVP_PKEY_encrypt(
        ctx: *mut EVP_PKEY_CTX,
        out: *mut u8,
        out_len: *mut usize,
        in_: *const u8,
        in_len: usize,
    ) -> c_int;

    pub fn EVP_PKEY_decrypt(
        ctx: *mut EVP_PKEY_CTX,
        out: *mut u8,
        out_len: *mut usize,
        in_: *const u8,
        in_len: usize,
    ) -> c_int;

    pub fn PEM_read_bio_PUBKEY(
        bp: *mut BIO,
        x: *mut *mut EVP_PKEY,
        cb: pem_password_cb,
        u: *mut c_void,
    ) -> *mut EVP_PKEY;

    pub fn d2i_AutoPrivateKey(
        out: *mut *mut EVP_PKEY,
        inp: *mut *const u8,
        len: c_long,
    ) -> *mut EVP_PKEY;

    pub fn d2i_PUBKEY(
        out: *mut *mut EVP_PKEY,
        inp: *mut *const u8,
        len: c_long,
    ) -> *mut EVP_PKEY;

    pub fn PEM_read_bio_PrivateKey(
        bp: *mut BIO,
        x: *mut *mut EVP_PKEY,
        cb: pem_password_cb,
        u: *mut c_void,
    ) -> *mut EVP_PKEY;

    pub fn PEM_read_bio_X509(
        bp: *mut BIO,
        x: *mut *mut X509,
        cb: pem_password_cb,
        u: *mut c_void,
    ) -> *mut X509;

    pub fn d2i_X509(
        out: *mut *mut X509,
        inp: *mut *const u8,
        len: c_long,
    ) -> *mut X509;

    pub fn X509_check_host(
        x: *mut X509,
        chk: *const c_char,
        chklen: usize,
        flags: c_uint,
        peername: *mut *mut c_char,
    ) -> c_int;

    pub fn X509_STORE_CTX_init(
        ctx: *mut X509_STORE_CTX,
        store: *mut X509_STORE,
        x509: *mut X509,
        chain: *mut stack_st_X509,
    ) -> c_int;
}