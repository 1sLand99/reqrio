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
DLL.new_http.restype = c_void_p

DLL.set_header_json.argtypes = [c_void_p, c_char_p]
DLL.set_header_json.restype = c_int

DLL.add_header.argtypes = [c_void_p, c_char_p, c_char_p]
DLL.add_header.restype = c_int

DLL.set_alpn.argtypes = [c_void_p, c_char_p]
DLL.set_alpn.restype = c_int

# DLL.set_fingerprint.argtypes = [c_void_p, c_char_p]
# DLL.set_fingerprint.restype = c_int

# DLL.set_ja3.argtypes = [c_void_p, c_char_p]
# DLL.set_ja3.restype = c_int

DLL.set_random_fingerprint.argtypes = [c_void_p]
DLL.set_random_fingerprint.restype = c_int

DLL.set_proxy.argtypes = [c_void_p, c_char_p]
DLL.set_proxy.restype = c_int

DLL.set_url.argtypes = [c_void_p, c_char_p]
DLL.set_url.restype = c_int

DLL.set_data.argtypes = [c_void_p, c_char_p]
DLL.set_data.restype = c_int

DLL.set_json.argtypes = [c_void_p, c_char_p]
DLL.set_json.restype = c_int

DLL.set_bytes.argtypes = [c_void_p, c_char_p, c_uint32]
DLL.set_bytes.restype = c_int

DLL.set_content_type.argtypes = [c_void_p, c_char_p]
DLL.set_content_type.restype = c_int

DLL.set_cookie.argtypes = [c_void_p, c_char_p]
DLL.set_cookie.restype = c_int

DLL.add_cookie.argtypes = [c_void_p, c_char_p, c_char_p]
DLL.add_cookie.restype = c_int

DLL.set_timeout.argtypes = [c_void_p, c_char_p]
DLL.set_timeout.restype = c_int

DLL.add_param.argtypes = [c_void_p, c_char_p]
DLL.add_param.restype = c_int

DLL.get.argtypes = [c_void_p]
DLL.get.restype = c_void_p

DLL.post.argtypes = [c_void_p]
DLL.post.restype = c_void_p

DLL.options.argtypes = [c_void_p]
DLL.options.restype = c_void_p

DLL.put.argtypes = [c_void_p]
DLL.put.restype = c_void_p

DLL.head.argtypes = [c_void_p]
DLL.head.restype = c_void_p

DLL.trach.argtypes = [c_void_p]
DLL.trach.restype = c_void_p

DLL.destroy.argtypes = [c_void_p]

DLL.free_pointer.argtypes = [c_void_p]

CALLBACK = CFUNCTYPE(None, POINTER(c_char), c_uint32)
DLL.register.argtypes = [c_void_p, CALLBACK]
DLL.register.restype = c_int

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

DLL.reconnect.argtypes = [c_void_p]
DLL.reconnect.restype = c_int

# websocket
DLL.build_ws.argtypes = []
DLL.build_ws.restype = c_void_p

DLL.ws_add_header.argtypes = [c_void_p, c_char_p, c_char_p]
DLL.ws_add_header.restype = c_int

DLL.ws_set_proxy.argtypes = [c_void_p, c_char_p]
DLL.ws_set_proxy.restype = c_int

DLL.ws_set_url.argtypes = [c_void_p, c_char_p]
DLL.ws_set_url.restype = c_int

DLL.ws_set_uri.argtypes = [c_void_p, c_char_p]
DLL.ws_set_uri.restype = c_int

DLL.open_ws.argtypes = [c_void_p]
DLL.open_ws.restype = c_void_p

DLL.open_ws_raw.argtypes = [c_char_p, c_char_p]
DLL.open_ws_raw.restype = c_void_p

DLL.ws_read.argtypes = [c_void_p]
DLL.ws_read.restype = c_void_p

DLL.ws_write.argtypes = [c_void_p, c_int, c_bool, c_void_p]
DLL.ws_write.restype = c_int

DLL.ws_free.argtypes = [c_void_p]
