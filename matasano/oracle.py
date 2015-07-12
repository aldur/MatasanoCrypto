#!/usr/bin/env/ python
# encoding: utf-8

__author__ = 'aldur'

import random
import matasano.blocks


def random_aes_key() -> bytes:
    """Generate a random AES key (16 bytes)

    :return: 16 bytes.
    """
    return bytes(random.randint(0, 255) for _ in range(16))


def random_bytes_random_range(low: int, high: int) -> bytes:
    """
    Generate low to high random bytes.

    :param low: The minimum number of bytes to generate.
    :param high: The maximum (inclusive) number of bytes to generate.
    :return: A random range of random bytes s.t. low <= len(output) <= max.
    """
    return bytes(
        random.randint(0, 255)
        for _
        in range(0, random.randint(low, high))
    )


def aes_ecb_cbc(b: bytes) -> bytes:
    """An encryption oracle that randomly encrypts with AES ECB or AES CBC.

    Choose at random between AES ECB and AES CBC (by tossing a coin).
    Generate a random key.
    Add padding before and after b.
    Encrypt b.
    Return.

    :param b: The buffer to be encrypted. Must be a multiple of 16.
    :returns: An encryption of b.
    """
    assert b

    key = random_aes_key()
    cipher = matasano.blocks.aes_ecb if \
        random.random() >= 0.5 \
        else matasano.blocks.aes_cbc

    # Add some randomness
    b = random_bytes_random_range(5, 10) + b + random_bytes_random_range(5, 10)
    # Pad if necessary
    b = matasano.blocks.pkcs(b, 16)

    return cipher(key, b)
