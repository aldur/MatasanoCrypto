#!/usr/bin/env/ python
# encoding: utf-8

__author__ = 'aldur'

"""Handle operations supporting blocks here."""

from Crypto.Cipher import AES


def split_blocks(b: bytes, k_len: int) -> tuple:
    """Given a buffer and the key len, split the buffer into blocks.

    :param b: The input buffer.
    :param k_len: The key length.
    :returns: A list of byte buffers.

    """
    assert len(b) >= k_len

    return tuple(
        bytes(
            b[j] for j in range(i, len(b), k_len)
        ) for i in range(0, k_len)
    )


def any_equal_block(b: bytes) -> bool:
    """
    Check the buffer 16 bytes at the time.

    :param b: A bytes buffer.
    :return: True if two or more 16 bytes blocks are equal.
    """
    b = [b[i:i + 16] for i in range(0, len(b), 16)]
    return len(set(b)) != len(b)


def aes_ecb(key: bytes, b: bytes, decrypt: bool=False) -> bytes:
    """AES ECB mode.

    :param key: The cipher key.
    :param b: The buffer to be encrypted/decrypted.
    :param decrypt: Whether we should encrypt or decrypt.
    :returns: The encrypted/decrypted buffer.

    """
    assert len(b) % 16 == 0
    assert len(key) == 16

    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(b) if not decrypt else aes.decrypt(b)
