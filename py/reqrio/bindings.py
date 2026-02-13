import os
import sys
from ctypes import cdll, CFUNCTYPE, c_void_p, c_int, c_char, c_uint32, c_char_p, c_bool

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

DLL.ScReq_set_random_fingerprint.argtypes = [c_void_p]
DLL.ScReq_set_random_fingerprint.restype = c_int

DLL.ScReq_set_fingerprint.argtypes = [c_void_p, c_char_p]
DLL.ScReq_set_fingerprint.restype = c_int

DLL.ScReq_set_ja3.argtypes = [c_void_p, c_char_p]
DLL.ScReq_set_ja3.restype = c_int

DLL.ScReq_set_ja4.argtypes = [c_void_p, c_char_p]
DLL.ScReq_set_ja4.restype = c_int

DLL.ScReq_set_proxy.argtypes = [c_void_p, c_char_p]
DLL.ScReq_set_proxy.restype = c_int

DLL.ScReq_set_url.argtypes = [c_void_p, c_char_p]
DLL.ScReq_set_url.restype = c_int

DLL.ScReq_add_param.argtypes = [c_void_p, c_char_p]
DLL.ScReq_add_param.restype = c_int

DLL.ScReq_set_data.argtypes = [c_void_p, c_char_p]
DLL.ScReq_set_data.restype = c_int

DLL.ScReq_set_json.argtypes = [c_void_p, c_char_p]
DLL.ScReq_set_json.restype = c_int

DLL.ScReq_set_bytes.argtypes = [c_void_p, c_char_p, c_uint32]
DLL.ScReq_set_bytes.restype = c_int

DLL.ScReq_set_text.argtypes = [c_void_p, c_char_p]
DLL.ScReq_set_text.restype = c_int

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

DLL.ScReq_stream_io.argtypes = [c_void_p, c_int]
DLL.ScReq_stream_io.restype = c_void_p

DLL.ScReq_drop.argtypes = [c_void_p]

DLL.char_free.argtypes = [c_void_p]

ThreadCallback = CFUNCTYPE(None, c_uint32)
DLL.new_thread_pool.argtypes = [c_void_p, c_int]
DLL.new_thread_pool.restype = c_void_p

DLL.thread_pool_run.argtypes = [c_void_p, ThreadCallback]
DLL.thread_pool_run.restype = c_int

DLL.thread_pool_join.argtypes = [c_void_p]
DLL.thread_pool_join.restype = c_int

DLL.thread_pool_free.argtypes = [c_void_p]

DLL.thread_pool_acquire_lock.argtypes = [c_void_p]
DLL.thread_pool_acquire_lock.restype = c_int

DLL.thread_pool_release_lock.argtypes = [c_void_p]
DLL.thread_pool_release_lock.restype = c_int

DLL.thread_pool_set_timeout.argtypes = [c_void_p, c_int]
DLL.thread_pool_set_timeout.restype = c_int

DLL.thread_pool_set_max_active.argtypes = [c_void_p, c_int]
DLL.thread_pool_set_max_active.restype = c_int

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
