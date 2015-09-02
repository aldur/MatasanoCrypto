#!/usr/bin/env python
# encoding: utf-8

__author__ = "aldur"

"""Various utils."""

import base64
import re
import struct
import functools
import math
import random
import os.path


def hex_to_b64(hex_input: bytes) -> bytes:
    """Encode an hex byte string to base64.
    Don't worry, the first version implemented this in C. :)

    :param hex_input: The hex byte string to be encoded.
    :returns: The base64 encode of the string.

    """
    assert hex_input
    return base64.b64encode(hex_input)


def xor(a: bytes, b: bytes) -> bytes:
    """Return a xor b.

    :param a: Some bytes.
    :param b: Some bytes.
    :returns: a xor b
    """
    assert len(a) == len(b), \
        "Arguments must have same length."

    a, b = bytearray(a), bytearray(b)
    return bytes(map(lambda i: a[i] ^ b[i], range(len(a))))


def xor_char(b: bytes, c: chr) -> bytes:
    """XOR each byte of b with c.

    :param b: Some bytes.
    :param c: A single byte.
    :return: Each byte of b xorred against c.
    """
    assert b
    c = ord(c)
    assert 0 <= c <= 255

    return bytes(byte ^ c for byte in b)


def repeating_xor(b: bytes, key: bytes) -> bytes:
    """
    Encrypt b by using repeatedly the key.
    :param b: The buffer to encrypt.
    :param key: The key.
    :return: The result.
    """
    assert b
    assert key

    return bytes(
        b[i] ^ key[i % len(key)]
        for i in range(len(b))
    )


def escape_metas(s: str, meta: str, escape="\\") -> str:
    """
    Given a set of meta-characters,
    escape those chars from the given string.

    :param s: The string to be escaped.
    :param meta: The characters to be escaped.
    :param escape: The escape character (defaults to '\')
    :return: The escaped string.
    """
    assert s
    assert meta

    for m in meta:
        s = re.sub(
            re.escape(m),
            escape + m,
            s
        )
    return s


def key_value_parsing(s: str) -> dict:
    """
    key=value to dictionary parsing.
    Given a string of the form k_1=v_1&k_2=v_2,
    convert it to a dictionary.
    Best effort, skip malformed strings.

    :param s: The input string.
    :return: A dictionary from the input string.
    """
    assert s
    return {
        kv.split("=")[0]: kv.split("=")[1]
        for kv in s.split("&")
        if kv.count("=")
        }


def dictionary_to_kv(d: dict) -> str:
    """
    Given a dictionary, encode it in key value format.

    :param d: The dictionary to be encoded.
    :return: The encoded key-value version of the dictionary.
    """
    assert d
    return "&".join(
        "=".join((str(k), str(v))) for k, v in d.items()
    )


def int_32_lsb(x: int):
    """
    Get the 32 least significant bits.

    :param x: A number.
    :return: The 32 LSBits of x.
    """
    return int(0xFFFFFFFF & x)


def _int_bytes_conversion(
        argument,
        is_big_endian: bool,
        format_specifier: str,
        is_packing: bool
):
    """
    Encode/decode input to/from big/little endian bytes.

    :param argument: The argument to be encoded/decoded.
    :param is_big_endian: Whether to encode/decode in big endianess.
    :param format_specifier: The single struct element format specifier.
    :param is_packing: Whether to pack or unpack.
    """
    return struct.pack(
        "{}{}{}".format(
            ">" if is_big_endian else "<",
            len(argument),
            format_specifier,
        ), *argument
    ) if is_packing else struct.unpack(
        "{}{}{}".format(
            ">" if is_big_endian else "<",
            len(argument) // struct.calcsize(format_specifier),
            format_specifier,
        ), argument
    )


to_big_endian_unsigned_ints = functools.partial(
    _int_bytes_conversion,
    is_big_endian=True,
    format_specifier="I",
    is_packing=True
)

to_big_endian_unsigned_longs = functools.partial(
    _int_bytes_conversion,
    is_big_endian=True,
    format_specifier="Q",
    is_packing=True
)

to_little_endian_unsigned_ints = functools.partial(
    _int_bytes_conversion,
    is_big_endian=False,
    format_specifier="I",
    is_packing=True
)

to_little_endian_unsigned_longs = functools.partial(
    _int_bytes_conversion,
    is_big_endian=False,
    format_specifier="Q",
    is_packing=True
)

from_little_endian_unsigned_ints = functools.partial(
    _int_bytes_conversion,
    is_big_endian=False,
    format_specifier="I",
    is_packing=False
)

from_big_endian_unsigned_ints = functools.partial(
    _int_bytes_conversion,
    is_big_endian=True,
    format_specifier="I",
    is_packing=False
)


def left_rotate(n: int, b: int) -> int:
    """
    Left rotate the input by b.

    :param n: The input.
    :param b: The rotation factor.
    :return: The input after applying rotation.
    """
    return ((n << b) | ((n & 0xffffffff) >> (32 - b))) & 0xffffffff


def bytes_for_big_int(n: int) -> bytes:
    """
    Represent a big int in little endian bytes.

    :param n: The int to be represented in bytes.
    :return: A byte representation of the int.
    """
    assert n >= 0

    if n == 0:
        return bytes(1)
    elif n == 1:
        return n.to_bytes(1, 'little')
    else:
        return n.to_bytes(
            math.ceil(math.log(n, 255)),
            'little'
        )


def get_password_wordlist() -> list:
    """
    Return a generator of password.
    If the system contains it,
    return words from:
        /usr/share/dict/words
    """
    file_path = "/usr/share/dict/words"
    if not os.path.isfile(file_path):
        return (w.encode("ascii") for w in ["foo", "bar", "password"])

    with open(file_path) as wordlist:
        return (w.rstrip().lower().encode("ascii") for w in wordlist.readlines())


def get_random_password() -> bytes:
    """
    Return a random password from
    those available.
    """
    return random.choice(
        list(get_password_wordlist())
    )
