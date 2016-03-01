#!/usr/bin/env/ python
# encoding: utf-8

"""Handle stream operations here."""

import matasano.prng

__author__ = 'aldur'


def mt19937_stream(key: int, b: bytes) -> bytes:
    """Encrypt/decrypt by using MT19937 generated numbers as key stream.

    :param key: The MT seed.
    :param b: The buffer to be encrypted/decrypted.
    :returns: The encrypted/decrypted buffer.
    """
    assert 0 <= key <= 2 ** 32 - 1
    assert bytes

    mt_prng = matasano.prng.MT19937(key)

    result = bytearray(b)
    i = 0

    while i < len(b):
        key = mt_prng.extract_number()  # 32 bits
        result[i] ^= key >> 24 & 0xff  # 8 MSB

        try:
            result[i + 1] ^= key >> 16 & 0xff
            result[i + 2] ^= key >> 8 & 0xff
            result[i + 3] ^= key & 0xff  # 8 LSB
        except IndexError:
            # Buffer ended
            pass

        i += 4

    return bytes(result)
