#!/usr/bin/env/ python
# encoding: utf-8

__author__ = 'aldur'

"""MAC-related tools."""

import functools

import matasano.hash
import matasano.util


def _mac_secret_prefix(
        key: bytes,
        message: bytes,
        hash_function
) -> bytes:
    """
    Authenticate the message by prefixing it with the secret key,
    and returning the resulting MAC digest.

    :param key: The secret key.
    :param message: The message to be authenticated.
    :param hash_function: The hash function.
    :return: The message authentication code.
    """
    return hash_function(
        key + message
    )

sha1_secret_prefix = functools.partial(
    _mac_secret_prefix,
    hash_function=matasano.hash.SHA1
)

md4_secret_prefix = functools.partial(
    _mac_secret_prefix,
    hash_function=matasano.hash.MD4
)


def _hmac(
        key: bytes,
        message: bytes,
        hash_function,
        block_size: int
):
    """
    Return the HMAC signature of the message,
    produced by using the given key and mac function.

    :param key: The secret key.
    :param message: The message to be authenticated.
    :param hash_function: The MAC function.
    :param block_size: The bytes length produced by the hash function.
    :return: The message authentication code.
    """
    assert all((key, message, hash_function, block_size))

    opad = bytes(0x5c for _ in range(block_size))
    ipad = bytes(0x36 for _ in range(block_size))

    if len(key) > block_size:  # Trimming
        key = hash_function(key)
    if len(key) < block_size:  # 0-Padding
        key = key + bytes(block_size - len(key))

    return hash_function(
        matasano.util.xor(key, opad) + hash_function(
            matasano.util.xor(key, ipad) + message
        )
    )


hmac_sha1 = functools.partial(
    _hmac,
    hash_function=matasano.hash.SHA1,
    block_size=64
)


hmac_sha256 = functools.partial(
    _hmac,
    hash_function=matasano.hash.SHA256,
    block_size=64
)
