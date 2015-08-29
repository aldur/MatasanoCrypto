#!/usr/bin/env/ python
# encoding: utf-8

__author__ = 'aldur'

"""Hashing related tools."""

import struct


def _left_rotate(n: int, b: int) -> int:
    """
    Left rotate the input by b.

    :param n: The input.
    :param b: The rotation factor.
    :return: The input after applying rotation.
    """
    return ((n << b) | (n >> (32 - b))) & 0xffffffff


def sha1(b: bytes) -> bytes:
    """
    SHA-1 Hashing Function.
    Credits: https://github.com/ajalt/python-sha1/blob/master/sha1.py

    :param b: The input buffer.
    :return: The SHA-1 digest of the input message.
    """
    # Initialize variables:
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    # Pre-processing:
    original_byte_len = len(b)
    original_bit_len = original_byte_len * 8
    # append the bit '1' to the message
    b += b'\x80'

    # append 0 <= k < 512 bits '0', so that the resulting message length (in bits)
    #    is congruent to 448 (mod 512)
    b += b'\x00' * ((56 - (original_byte_len + 1) % 64) % 64)

    # append length of message (before pre-processing), in bits, as 64-bit big-endian integer
    b += struct.pack(b'>Q', original_bit_len)
    # Process the message in successive 512-bit chunks:
    # break message into 512-bit chunks
    for i in range(0, len(b), 64):
        w = [0] * 80
        # break chunk into sixteen 32-bit big-endian words w[i]
        for j in range(16):
            w[j] = struct.unpack(b'>I', b[i + j * 4:i + j * 4 + 4])[0]
        # Extend the sixteen 32-bit words into eighty 32-bit words:
        for j in range(16, 80):
            w[j] = _left_rotate(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1)

        # Initialize hash value for this chunk:
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        for j in range(80):
            if 0 <= j <= 19:
                # Use alternative 1 for f from FIPS PB 180-1 to avoid ~
                f = d ^ (b & (c ^ d))
                k = 0x5A827999
            elif 20 <= j <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= j <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:  # 60 <= j <= 79
                f = b ^ c ^ d
                k = 0xCA62C1D6

            a, b, c, d, e = (
                (_left_rotate(a, 5) + f + e + k + w[j]) & 0xffffffff,
                a,
                _left_rotate(b, 30),
                c,
                d
            )

        # Add this chunk's hash to result so far:
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff

    # Produce the final hash value (big-endian):
    return struct.pack(">5I", h0, h1, h2, h3, h4)
