import json
from ctypes import *

from reqrio.alpn import ALPN
from reqrio.bindings import DLL, CALLBACK
from reqrio.method import Method
from reqrio.response import Response
from reqrio.rcode import url_encode
from reqrio import util


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
                    connect_times: int = 3, handle_times: int = 3):
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
        r = self.dll.ScReq_add_header(self.hid, name.encode('utf-8'), value.encode('utf-8'))
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

    @staticmethod
    def _format_body(data: dict = None, jd: dict = None, bs: bytes = None, ct: str = None):
        if data is not None:
            res = ''
            for k in data.keys():
                res += k
                res += "="
                res += url_encode(json.dumps(data[k]))
                res += "&"
            if res.endswith("&"):
                res = res[:-1]
            ln, u8 = util.str_to_u8(res)
            if ct is None:
                return u8, ln, "application/x-www-form-urlencoded"
            else:
                return u8, ln, ct
        if jd is not None:
            ln, u8 = util.dict_to_u8(jd)
            if ct is None:
                return u8, ln, "application/json"
            else:
                return u8, ln, ct

        if bs is not None:
            ln, u8 = util.bytes_to_u8(bs)
            if ct is None:
                return u8, ln, "application/octet-stream"
            else:
                return u8, ln, ct
        ln, u8 = util.bytes_to_u8(bytes([]))
        return u8, ln, "application/octet-stream"

    def send_request(self, method: Method, url: str, data: dict = None, json: dict = None, bs: bytes = None,
                     content_type: str = None):
        u8, ln, ct = self._format_body(data, json, bs, content_type)
        resp = self.dll.ScReq_stream_io(self.hid, method.value, url.encode('utf-8'), u8, ln, ct.encode('utf-8'))
        bs = string_at(resp).decode('utf-8')
        self.dll.char_free(resp)
        try:
            import json
            response = Response(json.loads(bytes.fromhex(bs)))
            response.header.method = method
            return response
        except Exception as _:
            raise Exception(bs)

    def get(self, url: str, data: dict = None, json: dict = None, bs: bytes = None,
            content_type: str = None) -> Response:
        return self.send_request(Method.GET, url, data, json, bs, content_type)

    def post(self, url: str, data: dict = None, json: dict = None, bs: bytes = None,
             content_type: str = None) -> Response:
        return self.send_request(Method.POST, url, data, json, bs, content_type)

    def put(self, url: str, data: dict = None, json: dict = None, bs: bytes = None,
            content_type: str = None) -> Response:
        return self.send_request(Method.PUT, url, data, json, bs, content_type)

    def head(self, url: str, data: dict = None, json: dict = None, bs: bytes = None,
             content_type: str = None) -> Response:
        return self.send_request(Method.HEAD, url, data, json, bs, content_type)

    def delete(self, url: str, data: dict = None, json: dict = None, bs: bytes = None,
               content_type: str = None) -> Response:
        return self.send_request(Method.DELETE, url, data, json, bs, content_type)

    def options(self, url: str, data: dict = None, json: dict = None, bs: bytes = None,
                content_type: str = None) -> Response:
        return self.send_request(Method.OPTIONS, url, data, json, bs, content_type)

    def trace(self, url: str, data: dict = None, json: dict = None, bs: bytes = None,
              content_type: str = None) -> Response:
        return self.send_request(Method.TRACE, url, data, json, bs, content_type)

    def patch(self, url: str, data: dict = None, json: dict = None, bs: bytes = None,
              content_type: str = None) -> Response:
        return self.send_request(Method.PATCH, url, data, json, bs, content_type)

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
