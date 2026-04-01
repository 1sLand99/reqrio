import os
import sys
from ctypes import cdll, CFUNCTYPE, c_void_p, c_int, c_char, c_uint32, c_char_p, c_bool, c_ubyte, c_size_t

from _ctypes import POINTER

base = os.path.dirname(__file__)
if sys.platform == 'win32':
    dll_path = os.path.join(base, 'reqrio.dll')
elif sys.platform == 'linux':
    dll_path = os.path.join(base, 'libreqrio.so')
else:
    raise Exception('unsupported platform')
DLL = cdll.LoadLibrary(dll_path)

# 初始化函数
DLL.ScReq_new.restype = c_void_p

DLL.ScReq_set_header_json.argtypes = [c_void_p, c_char_p]
DLL.ScReq_set_header_json.restype = c_int

DLL.ScReq_add_header.argtypes = [c_void_p, c_char_p, c_char_p]
DLL.ScReq_add_header.restype = c_int

DLL.ScReq_set_alpn.argtypes = [c_void_p, c_char_p]
DLL.ScReq_set_alpn.restype = c_int

DLL.ScReq_set_verify.argtypes = [c_void_p, c_bool]

DLL.ScReq_set_random_fingerprint.argtypes = [c_void_p, c_char_p]
DLL.ScReq_set_random_fingerprint.restype = c_int

DLL.ScReq_set_fingerprint.argtypes = [c_void_p, c_char_p, c_char_p]
DLL.ScReq_set_fingerprint.restype = c_int

DLL.ScReq_set_ja3.argtypes = [c_void_p, c_char_p, c_char_p]
DLL.ScReq_set_ja3.restype = c_int

DLL.ScReq_set_ja4.argtypes = [c_void_p, c_char_p, c_char_p]
DLL.ScReq_set_ja4.restype = c_int

DLL.ScReq_set_proxy.argtypes = [c_void_p, c_char_p]
DLL.ScReq_set_proxy.restype = c_int

DLL.ScReq_add_param.argtypes = [c_void_p, c_char_p]
DLL.ScReq_add_param.restype = c_int

DLL.ScReq_set_timeout.argtypes = [c_void_p, c_char_p]
DLL.ScReq_set_timeout.restype = c_int

DLL.ScReq_set_cookie.argtypes = [c_void_p, c_char_p]
DLL.ScReq_set_cookie.restype = c_int

DLL.ScReq_add_cookie.argtypes = [c_void_p, c_char_p, c_char_p]
DLL.ScReq_add_cookie.restype = c_int

CALLBACK = CFUNCTYPE(None, POINTER(c_char), c_uint32)
DLL.ScReq_set_callback.argtypes = [c_void_p, CALLBACK]
DLL.ScReq_set_callback.restype = c_int

DLL.ScReq_reconnect.argtypes = [c_void_p]
DLL.ScReq_reconnect.restype = c_int

DLL.ScReq_stream_io.argtypes = [c_void_p, c_int, c_void_p, POINTER(c_ubyte), c_size_t, c_void_p]
DLL.ScReq_stream_io.restype = c_void_p

DLL.ScReq_drop.argtypes = [c_void_p]

DLL.char_free.argtypes = [c_void_p]

# websocket
DLL.ws_build.argtypes = []
DLL.ws_build.restype = c_void_p

DLL.ws_add_header.argtypes = [c_void_p, c_char_p, c_char_p]
DLL.ws_add_header.restype = c_int

DLL.ws_set_proxy.argtypes = [c_void_p, c_char_p]
DLL.ws_set_proxy.restype = c_int

DLL.ws_set_url.argtypes = [c_void_p, c_char_p]
DLL.ws_set_url.restype = c_int

DLL.ws_set_uri.argtypes = [c_void_p, c_char_p]
DLL.ws_set_uri.restype = c_int

DLL.ws_open.argtypes = [c_void_p]
DLL.ws_open.restype = c_void_p

DLL.ws_open_raw.argtypes = [c_char_p, c_char_p]
DLL.ws_open_raw.restype = c_void_p

DLL.ws_read.argtypes = [c_void_p]
DLL.ws_read.restype = c_void_p

DLL.ws_write.argtypes = [c_void_p, c_int, c_bool, c_void_p]
DLL.ws_write.restype = c_int

DLL.ws_close.argtypes = [c_void_p]

# reqtls

DLL.Cipher_new.argtypes = [c_int]
DLL.Cipher_new.restype = c_void_p

DLL.Cipher_set_secret_key.argtypes = [
    c_void_p,
    POINTER(c_ubyte),
    c_size_t,
    POINTER(c_ubyte),
    c_size_t
]
DLL.Cipher_set_secret_key.restype = c_int

DLL.Cipher_encrypt.argtypes = [
    c_void_p,
    POINTER(c_ubyte),
    c_size_t,
    POINTER(POINTER(c_ubyte)),
    POINTER(c_size_t),
]
DLL.Cipher_encrypt.restype = c_int

DLL.Cipher_decrypt.argtypes = [
    c_void_p,
    POINTER(c_ubyte),
    c_size_t,
    POINTER(POINTER(c_ubyte)),
    POINTER(c_size_t),
]
DLL.Cipher_decrypt.restype = c_int

DLL.Cipher_free.argtypes = [c_void_p]

DLL.u8_free.argtypes = [POINTER(c_ubyte), c_size_t]
DLL.u8_free.restype = None

DLL.Hasher_new.argtypes = [c_int]
DLL.Hasher_new.restype = c_void_p

DLL.Hasher_update.argtypes = [c_void_p, POINTER(c_ubyte), c_size_t]
DLL.Hasher_update.restype = c_int

DLL.Hasher_finalize.argtypes = [c_void_p, POINTER(POINTER(c_ubyte)), POINTER(c_size_t)]
DLL.Hasher_finalize.restype = c_int

DLL.Hasher_free.argtypes = [c_void_p]

DLL.Hmac_new.argtypes = [POINTER(c_ubyte), c_size_t, c_int]
DLL.Hmac_new.restype = c_void_p

DLL.Hmac_update.argtypes = [c_void_p, POINTER(c_ubyte), c_size_t]
DLL.Hmac_update.restype = c_int

DLL.Hmac_finalize.argtypes = [c_void_p, POINTER(POINTER(c_ubyte)), POINTER(c_size_t)]
DLL.Hmac_finalize.restype = c_int

DLL.Hmac_free.argtypes = [c_void_p]

DLL.Base64_new.argtypes = []
DLL.Base64_new.restype = c_void_p

DLL.Base64_encode.argtypes = [c_void_p, POINTER(c_ubyte), c_size_t]
DLL.Base64_encode.restype = c_void_p

DLL.Base64_decode.argtypes = [c_void_p, POINTER(c_ubyte), c_size_t, POINTER(POINTER(c_ubyte)), POINTER(c_size_t)]
DLL.Base64_decode.restype = int

DLL.Base64_free.argtypes = [c_void_p]

DLL.url_encode.argtypes = [c_char_p]
DLL.url_encode.restype = c_void_p

DLL.url_decode.argtypes = [c_char_p]
DLL.url_decode.restype = c_void_p

DLL.hex_encode.argtypes = [POINTER(c_ubyte), c_size_t]
DLL.hex_encode.restype = c_void_p

DLL.hex_decode.argtypes = [c_char_p, POINTER(POINTER(c_ubyte)), POINTER(c_size_t)]
DLL.hex_decode.restype = int
