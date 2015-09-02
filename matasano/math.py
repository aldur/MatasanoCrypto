#!/usr/bin/env/ python
# encoding: utf-8

__author__ = 'aldur'

"""Math related tools."""

import Crypto.Util.number
import functools


def extended_gcd(a: int, b: int) -> tuple:
    """
    The extended Euclidean algorithm.
    Return GCD(a, b), x and y such that:

    ax + by = GCD(a, b)

    :param a: An integer.
    :param b: An integer.
    :return: The GCD and the x and y factors of the Bézout's identity.
    """
    last_remainder, remainder = abs(a), abs(b)
    x, last_x, y, last_y = 0, 1, 1, 0

    while remainder:
        last_remainder, (quotient, remainder) = remainder, divmod(last_remainder, remainder)
        x, last_x = last_x - quotient * x, x
        y, last_y = last_y - quotient * y, y

    return (
        last_remainder,
        last_x * (-1 if a < 0 else 1),
        last_y * (-1 if b < 0 else 1)
    )


def modinv(a: int, m: int):
    """
    Compute the inverse mod(m) of a.

    :param a: The integer whose inverse has to be found.
    :param m: The modulo.
    :return: The inverse of a mod(m).
    :raise Exception: If an inverse doesn't exist.
    """
    assert m > 1

    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception("{} is not invertible mod({}).".format(a, m))
    return x % m


random_big_prime = functools.partial(
    Crypto.Util.number.getStrongPrime,
    N=1024  # bits
)
