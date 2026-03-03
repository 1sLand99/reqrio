from reqrio.alpn import ALPN
from reqrio.response import Response
from reqrio.session import Session
from reqrio.method import Method
from reqrio.pool import ThreadPool
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


def get(url: str, headers: dict, params: dict = None, data: dict = None, json: dict = None,
        alpn=ALPN.HTTP11) -> Response:
    s = Session(alpn)
    s.set_url(url)
    if params is not None:
        for k in params.keys():
            s.add_param(k, str(params[k]))

    if data is not None:
        s.set_data(data)

    if json is not None:
        s.set_json(json)

    s.set_header_json(headers)
    resp = s.get()
    s.close()
    return resp


def post(url: str, headers: dict, params: dict = None, data: dict = None, json: dict = None,
         alpn=ALPN.HTTP11) -> Response:
    s = Session(alpn)
    s.set_url(url)
    if params is not None:
        for k in params.keys():
            s.add_param(k, str(params[k]))

    if data is not None:
        s.set_data(data)

    if json is not None:
        s.set_json(json)

    s.set_header_json(headers)

    resp = s.post()
    s.close()
    return resp


def en_b64(ct: CipherType, data: Union[str, bytes], key: Union[str, bytes], iv: Union[str, bytes] = None) -> str:
    cipher = Cipher(ct, key, iv)
    en_bs = cipher.encrypt(data)
    return b64encode(en_bs)


def de_b64(ct: CipherType, data: str, key: Union[str, bytes], iv: Union[str, bytes] = None) -> bytes:
    de_b64 = b64decode(data)
    cipher = Cipher(ct, key, iv)
    return cipher.decrypt(de_b64)

def en_hex(ct: CipherType, data: Union[str, bytes], key: Union[str, bytes], iv: Union[str, bytes] = None) -> str:
    cipher = Cipher(ct, key, iv)
    en_bs = cipher.encrypt(data)
    return hex_encode(en_bs)


def de_hex(ct: CipherType, data: str, key: Union[str, bytes], iv: Union[str, bytes] = None) -> bytes:
    de_b64 = hex_decode(data)
    cipher = Cipher(ct, key, iv)
    return cipher.decrypt(de_b64)