import json
from _ctypes import Array
from ctypes import c_ubyte
from typing import Union
from reqrio import rcode


def dict_to_u8(data: dict) -> tuple[int, Array[c_ubyte]]:
    return str_to_u8(json.dumps(data))


def bytes_to_u8(data: bytes) -> tuple[int, Array[c_ubyte]]:
    data_len = len(data)
    data_u8 = (c_ubyte * data_len).from_buffer_copy(data)
    return data_len, data_u8


def str_to_u8(data: str) -> tuple[int, Array[c_ubyte]]:
    return bytes_to_u8(data.encode('utf-8'))


def str_bytes_to_u8(data: Union[str, bytes]) -> tuple[int, Array[c_ubyte]]:
    if type(data) == str:
        return str_to_u8(data)
    else:
        return bytes_to_u8(data)


def urlencoded_str(data: dict) -> str:
    res = ''
    for k in data.keys():
        res += k
        res += "="
        res += rcode.url_encode(json.dumps(data[k]))
        res += "&"
    if res.endswith("&"):
        res = res[:-1]
    return res
