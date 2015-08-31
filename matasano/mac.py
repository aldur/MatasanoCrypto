#!/usr/bin/env/ python
# encoding: utf-8

__author__ = 'aldur'

"""MAC-related tools."""

import functools
import matasano.hash


def _mac_secret_prefix(
        key: bytes,
        message: bytes,
        mac
) -> bytes:
    """
    Authenticate the message by prefixing it with the secret key,
    and returning the resulting MAC digest.

    :param mac: The MAC function.
    :param key: The secret key.
    :param message: The message to be authenticated.
    :return: The message authentication code.
    """
    return mac(
        key + message
    )

sha1_secret_prefix = functools.partial(
    _mac_secret_prefix,
    mac=matasano.hash.SHA1
)

md4_secret_prefix = functools.partial(
    _mac_secret_prefix,
    mac=matasano.hash.MD4
)
