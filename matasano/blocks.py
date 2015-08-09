#!/usr/bin/env/ python
# encoding: utf-8

__author__ = 'aldur'

"""Handle operations supporting blocks here."""

import math

import matasano.util
import matasano.oracle

from Crypto.Cipher import AES


class BadPaddingException(Exception):
    """
    Throw this exception while detecting that a buffer
    provides an invalid padding.
    """
    pass


def ith_byte_block(block_size: int, i: int) -> int:
    """
    Return the block to which the byte at index i belongs.
    :param block_size: The block size.
    :param i: The index of the interesting byte.
    :return: The index of the block to which the byte at index i belongs.
    """
    assert block_size > 0
    assert i >= 0
    return i // block_size


def bytes_to_block(block_size: int, i: int) -> slice:
    """
    Given the block size and the desired block index,
    return the slice of bytes from 0 to the end of the given block.

    :param block_size: The block size.
    :param i: The block index.
    :return: slice of bytes from 0 to the end of the specified block index.
    """
    return slice(0, block_size * (i + 1))


def bytes_in_block(block_size: int, i: int) -> slice:
    """
    Given the block size and the desired block index,
    return the slice of interesting bytes.

    :param block_size: The block size.
    :param i: The block index.
    :return: slice of bytes pointing to given block index.
    """
    return slice(block_size * i, block_size * (i + 1))


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
    Given the block size, pad the input buffer,
    so that the result is a multiple of the specified size.

    Please note that this function will always pad,
    even if the buffer is already a multiple of the size.
    So, if size is 16 and b is "YELLOW SUBMARINE",
    it will be padded to:
    b'YELLOW SUBMARINE\x10\x10\x10\x10\...\x10\x10\x10\x10'

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


def un_pkcs(b: bytes, size: int) -> bytes:
    """
    PKCS#7 un_padding.
    Remove padding from the bytes.
    If padding is invalid, throws an exception.

    :param b: A padded buffer of bytes.
    :param size: The block size.
    :return: The buffer without padding.
    :raises: BadPaddingException
    """
    b = bytearray(b)
    padding = b[-1]
    if padding <= 0 or padding > size:
        raise BadPaddingException

    for i in range(-padding, 0):
        if b[i] != padding:
            raise BadPaddingException

    return bytes(b[:-padding])


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
        decrypt: bool=False,
        iv: bytes=None,
        random_iv: bool=False
) -> tuple:
    """AES CBC mode.

    :param key: The cipher key.
    :param b: The buffer to be encrypted/decrypted.
    :param decrypt: Whether we should encrypt or decrypt.
    :param iv: If not None, use this IV (and ignore random_iv param)
    :param random_iv: Whether we should use a random IV.
    :returns: The encrypted/decrypted buffer and the employed IV.

    """
    exit_buffer = b''
    if not iv:
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

    return exit_buffer, iv


def aes_ctr(
        key: bytes,
        b: bytes,
        nonce: int=0
) -> bytes:
    """AES CTR mode.

    :param key: The cipher key.
    :param b: The buffer to be encrypted/decrypted.
    :param nonce: The nonce to be used (defaults to 0).
    :returns: The encrypted/decrypted buffer.
    """
    assert len(key) % 16 == 0, \
        "Got wrong key size {}".format(len(key))
    assert b

    nonce = nonce.to_bytes(8, 'little', signed=False)
    result = b""

    for i in range(math.ceil(len(b) / 16)):
        aes = AES.new(key, AES.MODE_ECB)
        ctr = i.to_bytes(8, 'little', signed=False)

        block_slice = bytes_in_block(16, i)
        try:
            block = b[block_slice]
        except IndexError:
            block = b[block_slice.start:]

        result += matasano.util.xor(
            block,
            aes.encrypt(nonce + ctr)[:len(block)]
        )

    return result
