from reqrio.alpn import ALPN
from reqrio.response import Response
from reqrio.session import Session
from reqrio.method import Method
from reqrio.websocket import WebSocket, WsOpCode, WsFrame
from reqrio.cipher import CipherType, Cipher
from reqrio.hash import HashType, Hasher, Hmac
from reqrio.b64 import Base64, b64encode, b64decode
from typing import Union
from reqrio.rcode import url_encode, url_decode, hex_encode, hex_decode


# pyinstaller.exe -F --collect-binaries reqrio .\1.py

def _pyinstaller_hooks_dir():
    from pathlib import Path
    return [str(Path(__file__).with_name("hooks").resolve())]


def send(url: str, method: Method, headers: dict = None, params: dict = None, data: dict = None, json: dict = None,
         alpn=ALPN.HTTP11, verify: bool = True, proxy: str = None):
    req = session.Session(alpn, verify=verify)
    if proxy is not None:
        req.set_proxy(proxy)
    if headers is not None:
        req.set_headers(headers)
    resp = req.send_request(method, url, params=params, data=data, json=json)
    req.close()
    return resp


def get(url: str, headers: dict = None, params: dict = None, data: dict = None, json: dict = None,
        alpn=ALPN.HTTP11, verify: bool = True, proxy: str = None) -> Response:
    return send(url, Method.GET, headers, params, data, json, alpn, verify, proxy)


def post(url: str, headers: dict = None, params: dict = None, data: dict = None, json: dict = None,
         alpn=ALPN.HTTP11, verify: bool = True, proxy: str = None) -> Response:
    return send(url, Method.POST, headers, params, data, json, alpn, verify, proxy)


def en_b64(ct: CipherType, data: Union[str, bytes], key: Union[str, bytes], iv: Union[str, bytes] = None) -> str:
    cipher = Cipher(ct, key, iv)
    en_bs = cipher.encrypt(data)
    return b64encode(en_bs)


def de_b64(ct: CipherType, data: str, key: Union[str, bytes], iv: Union[str, bytes] = None) -> bytes:
    de_bs = b64decode(data)
    cipher = Cipher(ct, key, iv)
    return cipher.decrypt(de_bs)


def en_hex(ct: CipherType, data: Union[str, bytes], key: Union[str, bytes], iv: Union[str, bytes] = None) -> str:
    cipher = Cipher(ct, key, iv)
    en_bs = cipher.encrypt(data)
    return hex_encode(en_bs)


def de_hex(ct: CipherType, data: str, key: Union[str, bytes], iv: Union[str, bytes] = None) -> bytes:
    de_bs = hex_decode(data)
    cipher = Cipher(ct, key, iv)
    return cipher.decrypt(de_bs)
