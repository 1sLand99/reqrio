import json
from ctypes import *

from reqrio.alpn import ALPN
from reqrio.bindings import DLL, CALLBACK
from reqrio.method import Method
from reqrio.response import Response


class Session:
    # alpn值是字符串['http/1.1','h2']
    def __init__(self, alpn: ALPN = ALPN.HTTP11, rand_tls=False, token="", verify: bool = True):
        """
        :param
        :param alpn: HTTP版本
        :param rand_tls:使用随机指纹，仅订阅版本
        """
        self.dll = DLL
        self.callback = CALLBACK

        self.hid = self.dll.ScReq_new()
        if self.hid == -1: raise Exception('init fail')
        r = self.dll.ScReq_set_alpn(self.hid, alpn.value.encode('utf-8'))
        if r == -1: raise Exception('set alpn error')
        if rand_tls:
            r = self.dll.ScReq_set_random_fingerprint(self.hid, token.encode('utf-8'))
            if r == -1: raise Exception('set rand tls error')
        self.dll.ScReq_set_verify(self.hid, verify)

    def set_timeout(self, connect: int = 3000, read: int = 3000, write: int = 3000, handle: int = 30000,
                    connect_times: int = 3,
                    handle_times: int = 3):
        """
        :param connect: 连接超时,默认3s
        :param read: tcp读取超时,默认3s
        :param write: tcp写出超时,默认3s
        :param handle: 发包处理超时,默认30s
        :param connect_times: 尝试连接次数,默认3次
        :param handle_times:尝试处理次数,默认3次
        :return:
        """
        timeout = {
            'connect': connect,
            'read': read,
            'write': write,
            'handle': handle,
            'connect_times': connect_times,
            'handle_times': handle_times,
        }
        r = self.dll.ScReq_set_timeout(self.hid, json.dumps(timeout).encode('utf-8'))
        if r == -1: raise Exception('set timeout error')
        return

    def set_headers(self, header: dict):
        r = self.dll.ScReq_set_header_json(self.hid, json.dumps(header).encode('utf-8'))
        if r == -1: raise Exception('set header error')

    def add_header(self, name: str, value: str):
        r = self.dll.ScReq_set_header_json(self.hid, name.encode('utf-8'), value.encode('utf-8'))
        if r == -1: raise Exception('add header error')

    def set_fingerprint(self, fingerprint: str, token: str):
        """指纹数据，是tls握手过程中客户端发出的数据（转十六进制）hex(client_hello+client_key_exchanged+change_cipher_spec)"""
        r = self.dll.ScReq_set_fingerprint(self.hid, fingerprint.encode('utf-8'), token.encode('utf-8'))
        if r == -1: raise Exception('set fingerprint error')

    def set_ja3(self, ja3: str, token: str):
        r = self.dll.ScReq_set_ja3(self.hid, ja3.encode('utf-8'), token.encode('utf-8'))
        if r == -1: raise Exception('set ja3 error')

    def set_ja4(self, ja4: str, token: str):
        r = self.dll.ScReq_set_ja4(self.hid, ja4.encode('utf-8'), token.encode('utf-8'))
        if r == -1: raise Exception('set ja4 error')

    def set_proxy(self, proxy: str):
        """设置代理，格式:http://127.0.0.1:10000、socks5://127.0.0.1:10001、socks5://username@password127.0.0.1:10001"""
        r = self.dll.ScReq_set_proxy(self.hid, proxy.encode('utf-8'))
        if r == -1: raise Exception('set proxy error,proxy=' + proxy)

    def set_url(self, url: str):
        r = self.dll.ScReq_set_url(self.hid, url.encode('utf-8'))
        if r == -1: raise Exception('set url error,url=' + url)

    def set_data(self, data: dict):
        r = self.dll.ScReq_set_data(self.hid, json.dumps(data).encode('utf-8'))
        if r == -1: raise Exception('set data error')

    def set_json(self, data: dict):
        r = self.dll.ScReq_set_json(self.hid, json.dumps(data).encode('utf-8'))
        if r == -1: raise Exception('set json error')

    def set_bytes(self, bs: bytes):
        r = self.dll.ScReq_set_bytes(self.hid, bs, len(bs))
        if r == -1: raise Exception('set bytes error')

    def set_text(self, text: str):
        r = self.dll.ScReq_set_text(self.hid, text.encode('utf-8'))
        if r == -1: raise Exception('set text error')

    def set_cookie(self, cookie: str):
        r = self.dll.ScReq_set_cookie(self.hid, cookie.encode('utf-8'))
        if r == -1: raise Exception('set json error')

    def add_cookie(self, name: str, value: str):
        r = self.dll.ScReq_add_cookie(self.hid, name.encode('utf-8'), value.encode('utf-8'))
        if r == -1: raise Exception('set json error')

    def set_params(self, param: dict):
        for k in param.keys():
            self.add_param(k, str(param[k]))
        return

    def add_param(self, name: str, value: str):
        r = self.dll.ScReq_add_param(self.hid, name.encode('utf-8'), value.encode('utf-8'))
        if r == -1: raise Exception('add param error')

    def send_request(self, method: Method):
        resp = self.dll.ScReq_stream_io(self.hid, method.value)
        bs = string_at(resp).decode('utf-8')
        self.dll.char_free(resp)
        try:
            response = Response(json.loads(bytes.fromhex(bs)))
            response.header.method = method
            return response
        except Exception as _:
            raise Exception(bs)

    def get(self, url: str = None) -> Response:
        if url is not None:
            self.set_url(url)
        return self.send_request(Method.GET)

    def post(self, url: str = None) -> Response:
        if url is not None:
            self.set_url(url)
        return self.send_request(Method.POST)

    def put(self, url: str = None) -> Response:
        if url is not None:
            self.set_url(url)
        return self.send_request(Method.PUT)

    def head(self, url: str = None) -> Response:
        if url is not None:
            self.set_url(url)
        return self.send_request(Method.HEAD)

    def delete(self, url: str = None) -> Response:
        if url is not None:
            self.set_url(url)
        return self.send_request(Method.DELETE)

    def options(self, url: str = None) -> Response:
        if url is not None:
            self.set_url(url)
        return self.send_request(Method.OPTIONS)

    def trace(self, url: str = None) -> Response:
        if url is not None:
            self.set_url(url)
        return self.send_request(Method.TRACE)

    def patch(self, url: str = None) -> Response:
        if url is not None:
            self.set_url(url)
        return self.send_request(Method.PATCH)

    def session_reconnect(self):
        r = self.dll.reconnect(self.hid)
        if r == -1:
            raise Exception("重连失败")

    def open_stream(self, url: str, method: Method):
        from reqrio.stream import Stream

        self.set_url(url)
        return Stream(self, method)

    def close(self):
        """记得关闭资源，否则容易造成内存溢出"""
        self.dll.ScReq_drop(self.hid)
        self.hid = None

    def __del__(self):
        if hasattr(self, 'dll') and self.dll:
            self.dll.ScReq_drop(self.hid)
            self.hid = None
