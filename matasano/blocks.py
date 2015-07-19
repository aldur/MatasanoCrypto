#!/usr/bin/env/ python
# encoding: utf-8

__author__ = 'aldur'

"""Handle operations supporting blocks here."""

import matasano.util
import matasano.oracle
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


def pad_with_buffer(b: bytes, pad: bytes) -> bytes:
    """
    Get the bytes and pad them with an unknown string.

    :param b: The buffer to be padded.
    :param pad: The padding buffer.
    :return: b || pad, padded again to be a multiple of sixteen.
    """
    assert b
    assert pad

    b += pad
    b = pkcs(b, 16)

    return b


def pkcs(b: bytes, size: int) -> bytes:
    """
    PKCS#7 padding.
    Given the block size, pad bytes in order
    to be a multiple of the specified size.

    :param b: A buffer of bytes.
    :param size: The block size.
    :return: The padded buffer.
    """
    assert size <= 0xff

    b = bytearray(b)
    padding = size - (len(b) % size)
    for _ in range(padding):
        b.append(padding)

    return bytes(b)


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


def aes_cbc(
        key: bytes, b: bytes,
        decrypt: bool=False, random_iv: bool=False
) -> bytes:
    """AES CBC mode.

    :param key: The cipher key.
    :param b: The buffer to be encrypted/decrypted.
    :param decrypt: Whether we should encrypt or decrypt.
    :param random_iv: Whether we should use a random IV.
    :returns: The encrypted/decrypted buffer.

    """
    exit_buffer = b''
    iv = b'\x00' * 16 if not random_iv \
        else matasano.oracle.random_aes_key()

    previous = iv
    for i in range(0, len(b), 16):
        block = b[i:i + 16]

        if not decrypt:
            block = matasano.util.xor(block, previous)

        output = aes_ecb(key, block, decrypt)

        if not decrypt:
            exit_buffer += output
            previous = output
        else:
            exit_buffer += matasano.util.xor(output, previous)
            previous = block

    return exit_buffer
