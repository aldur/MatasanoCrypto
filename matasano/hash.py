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


def sha1_glue_padding(
        message: bytes,
        byte_len: int=None
) -> bytes:
    """
    The SHA1 hashing function pads the initial message
    with the bit \x80, k bits such that the resulting length
    is congruent to 448 (mod 512) and finally the message length.

    :param message: The input buffer.
    :param byte_len: The length to be appended in the padding.
    :return: The glue-padded input buffer.
    """
    if byte_len is None:
        byte_len = len(message)
    bit_len = byte_len * 8

    # append the bit '1' to the message
    padding = b'\x80'

    # append 0 <= k < 512 bits '0', so that the resulting message length (in bits)
    #    is congruent to 448 (mod 512)
    padding += b'\x00' * ((56 - (byte_len + 1) % 64) % 64)

    # append length of message (before pre-processing), in bits, as 64-bit big-endian integer
    padding += struct.pack(b'>Q', bit_len)

    return padding


def sha1(
        message: bytes,
        h0: int=0x67452301,
        h1: int=0xEFCDAB89,
        h2: int=0x98BADCFE,
        h3: int=0x10325476,
        h4: int=0xC3D2E1F0,
        byte_len: int=None
) -> bytes:
    """
    SHA-1 Hashing Function.
    Credits: https://github.com/ajalt/python-sha1/blob/master/sha1.py

    :param message: The input buffer.
    :param h0: The initial SHA1 register #0 value.
    :param h1: The initial SHA1 register #1 value.
    :param h2: The initial SHA1 register #2 value.
    :param h3: The initial SHA1 register #3 value.
    :param h4: The initial SHA1 register #4 value.
    :param byte_len: The message length to be put in the padding.
    :return: The SHA-1 digest of the input message.
    """
    # Pre-processing:
    message += sha1_glue_padding(message, byte_len)

    # Process the message in successive 512-bit chunks:
    # break message into 512-bit chunks
    for i in range(0, len(message), 64):
        w = [0] * 80
        # break chunk into sixteen 32-bit big-endian words w[i]
        for j in range(16):
            w[j] = struct.unpack(b'>I', message[i + j * 4:i + j * 4 + 4])[0]
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
