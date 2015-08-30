#!/usr/bin/env/ python
# encoding: utf-8

__author__ = 'aldur'

"""MAC-related tools."""

import matasano.hash


def sha1_secret_prefix(key: bytes, message: bytes) -> bytes:
    """
    Authenticate the message by prefixing it with the secret key,
    and returning the resulting SHA1 digest.

    :param key: The secret key.
    :param message: The message to be authenticated.
    :return: The message authentication code.
    """
    return matasano.hash.SHA1(
        key + message
    )
