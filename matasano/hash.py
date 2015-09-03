#!/usr/bin/env/ python
# encoding: utf-8

"""
Hashing related tools.
Credits: http://www.acooke.org/cute/PurePython0.html
License: GPL
"""

import hashlib
import struct
import functools

import matasano.util

__author__ = 'aldur'


def _md_pad_64(message: bytes, length_to_bytes, fake_byte_len: int=None) -> bytes:
    """The Merkle-Damgard padding function.

    :param message: The message to be padded.
    :param length_to_bytes: Function that converts the length to bytes.
    :param fake_byte_len: A possibly None fake byte length.
    :return: The padded message.
    """
    original_byte_len = len(message)
    message += b'\x80'
    message += b'\x00' * ((56 - (original_byte_len + 1) % 64) % 64)
    original_bit_len = (fake_byte_len if fake_byte_len else original_byte_len) * 8
    message += bytes(length_to_bytes(original_bit_len))
    return message


def _make_md_hash_64(compress, state_to_hash, length_to_bytes) -> bytes:
    """
    Apply the Merkle-Damgard transform.

    :param compress: The compression function.
    :param state_to_hash: Function that converts the hash state to the digest.
    :param length_to_bytes: Function that converts the length to bytes.
    :return: The message hash digest.
    """

    def _md_hash(
            message: bytes,
            state: list=None,
            fake_byte_len: int=None
    ) -> bytes:
        message = _md_pad_64(message, length_to_bytes, fake_byte_len=fake_byte_len)
        for i in range(0, len(message), 64):
            state = compress(message[i:i + 64], state)
        return state_to_hash(state)

    return _md_hash


def _sha1_compress(block: bytes, state: list=None) -> list:
    """
    The inner SHA1 compress function.

    :param block: The block to be compressed.
    :param state: The current SHA1 state.
    :return: The compressed block.
    """
    if not state:
        state = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0

    a, b, c, d, e = h0, h1, h2, h3, h4 = state

    w = [0] * 80
    # break chunk into sixteen 32-bit big-endian words w[i]
    for j in range(16):
        w[j] = struct.unpack('>I', block[j * 4:j * 4 + 4])[0]
    # extend the sixteen 32-bit words into eighty 32-bit words:
    for j in range(16, 80):
        w[j] = matasano.util.left_rotate(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1)

    for i in range(80):
        if i < 20:
            # use alternative 1 for f from FIPS PB 180-1 to avoid ~
            f = d ^ (b & (c ^ d))
            k = 0x5A827999
        elif 20 <= i < 40:
            f = b ^ c ^ d
            k = 0x6ED9EBA1
        elif 40 <= i < 60:
            f = (b & c) | (b & d) | (c & d)
            k = 0x8F1BBCDC
        else:  # 60 <= i
            f = b ^ c ^ d
            k = 0xCA62C1D6

        a, b, c, d, e = (
            (matasano.util.left_rotate(a, 5) + f + e + k + w[i]) & 0xffffffff,
            a,
            matasano.util.left_rotate(b, 30),
            c,
            d
        )

    return [
        (h0 + a) & 0xffffffff,
        (h1 + b) & 0xffffffff,
        (h2 + c) & 0xffffffff,
        (h3 + d) & 0xffffffff,
        (h4 + e) & 0xffffffff
    ]


"""
The full-fledged SHA1 function.
"""
# Convert length to Big Endian 64-bit word
_sha1_length_to_bytes = \
    lambda length: matasano.util.to_big_endian_unsigned_longs([length])

SHA1 = _make_md_hash_64(
    compress=_sha1_compress,
    # Convert state to Big Endian 32-bit words
    state_to_hash=matasano.util.to_big_endian_unsigned_ints,
    length_to_bytes=_sha1_length_to_bytes
)
sha1_pad = functools.partial(
    _md_pad_64,
    length_to_bytes=_sha1_length_to_bytes
)


def _md4_compress(block: bytes, state: list=None) -> list:
    """
    The MD4 compression function.

    :param block: The block to be compressed.
    :param state: The function internal state.
    :return: The compressed block.
    """
    def _f1(_a, _b, _c, _d, k, s, big_x):
        def _f(_x, _y, _z):
            return _x & _y | ~_x & _z

        return matasano.util.left_rotate(_a + _f(_b, _c, _d) + big_x[k], s)

    def _f2(_a, _b, _c, _d, k, s, big_x):
        def _g(_x, _y, _z):
            return _x & _y | _x & _z | _y & _z

        return matasano.util.left_rotate(_a + _g(_b, _c, _d) + big_x[k] + 0x5a827999, s)

    def _f3(_a, _b, _c, _d, k, s, big_x):
        def _h(_x, _y, _z):
            return _x ^ _y ^ _z

        return matasano.util.left_rotate(_a + _h(_b, _c, _d) + big_x[k] + 0x6ed9eba1, s)

    if not state:
        state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]

    a, b, c, d = h0, h1, h2, h3 = state

    x = matasano.util.from_little_endian_unsigned_ints(block)

    a = _f1(a, b, c, d, 0, 3, x)
    d = _f1(d, a, b, c, 1, 7, x)
    c = _f1(c, d, a, b, 2, 11, x)
    b = _f1(b, c, d, a, 3, 19, x)
    a = _f1(a, b, c, d, 4, 3, x)
    d = _f1(d, a, b, c, 5, 7, x)
    c = _f1(c, d, a, b, 6, 11, x)
    b = _f1(b, c, d, a, 7, 19, x)
    a = _f1(a, b, c, d, 8, 3, x)
    d = _f1(d, a, b, c, 9, 7, x)
    c = _f1(c, d, a, b, 10, 11, x)
    b = _f1(b, c, d, a, 11, 19, x)
    a = _f1(a, b, c, d, 12, 3, x)
    d = _f1(d, a, b, c, 13, 7, x)
    c = _f1(c, d, a, b, 14, 11, x)
    b = _f1(b, c, d, a, 15, 19, x)

    a = _f2(a, b, c, d, 0, 3, x)
    d = _f2(d, a, b, c, 4, 5, x)
    c = _f2(c, d, a, b, 8, 9, x)
    b = _f2(b, c, d, a, 12, 13, x)
    a = _f2(a, b, c, d, 1, 3, x)
    d = _f2(d, a, b, c, 5, 5, x)
    c = _f2(c, d, a, b, 9, 9, x)
    b = _f2(b, c, d, a, 13, 13, x)
    a = _f2(a, b, c, d, 2, 3, x)
    d = _f2(d, a, b, c, 6, 5, x)
    c = _f2(c, d, a, b, 10, 9, x)
    b = _f2(b, c, d, a, 14, 13, x)
    a = _f2(a, b, c, d, 3, 3, x)
    d = _f2(d, a, b, c, 7, 5, x)
    c = _f2(c, d, a, b, 11, 9, x)
    b = _f2(b, c, d, a, 15, 13, x)

    a = _f3(a, b, c, d, 0, 3, x)
    d = _f3(d, a, b, c, 8, 9, x)
    c = _f3(c, d, a, b, 4, 11, x)
    b = _f3(b, c, d, a, 12, 15, x)
    a = _f3(a, b, c, d, 2, 3, x)
    d = _f3(d, a, b, c, 10, 9, x)
    c = _f3(c, d, a, b, 6, 11, x)
    b = _f3(b, c, d, a, 14, 15, x)
    a = _f3(a, b, c, d, 1, 3, x)
    d = _f3(d, a, b, c, 9, 9, x)
    c = _f3(c, d, a, b, 5, 11, x)
    b = _f3(b, c, d, a, 13, 15, x)
    a = _f3(a, b, c, d, 3, 3, x)
    d = _f3(d, a, b, c, 11, 9, x)
    c = _f3(c, d, a, b, 7, 11, x)
    b = _f3(b, c, d, a, 15, 15, x)

    return [
        (h0 + a) & 0xffffffff,
        (h1 + b) & 0xffffffff,
        (h2 + c) & 0xffffffff,
        (h3 + d) & 0xffffffff
    ]


"""
The full fledged MD4 function.
"""
# Convert length to Little Endian 64-bit word
_md4_length_to_bytes = \
    lambda length: matasano.util.to_little_endian_unsigned_longs([length])
MD4 = _make_md_hash_64(
    compress=_md4_compress,
    state_to_hash=matasano.util.to_little_endian_unsigned_ints,
    length_to_bytes=_md4_length_to_bytes
)
md4_pad = functools.partial(
    _md_pad_64,
    length_to_bytes=_md4_length_to_bytes
)


def SHA256(b: bytes) -> bytes:
    """
    Wrapper around native Python implementation.

    :param b: The message to be hashed.
    :return: The hash digest of the message.
    """
    h = hashlib.sha256()
    h.update(b)
    return h.digest()
