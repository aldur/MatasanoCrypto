#!/usr/bin/env python
# encoding: utf-8

__author__ = "aldur"

"""Various utils."""

import base64


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
