#!/usr/bin/env/ python
# encoding: utf-8

"""Math related tools."""

import Crypto.Util.number
import functools

__author__ = 'aldur'


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


def modinv(a: int, m: int) -> int:
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
        raise ValueError("{} is not invertible mod({}).".format(a, m))
    return x % m


def integer_kth_root(n: int, k: int) -> int:
    """
    Find the integer k-th root of n.
    Credits:
    http://stackoverflow.com/questions/15978781/how-to-find-integer-nth-roots
    Solution based on Newton's method.

    :param k: The root exponent.
    :param n: The number to be rooted.
    :return: The greatest integer less than or equal to the k-th root of n.
    """
    u, s = n, n + 1
    while u < s:
        s = u
        t = (k - 1) * s + n // pow(s, k - 1)
        u = t // k
    return s


integer_cube_root = functools.partial(
    integer_kth_root,
    k=3
)


def random_big_prime(N: int=1024, e=None) -> int:
    """
    Generate a random big prime of N bits.
    :param N: The number of bits composing N.
    :param e: Useful to avoid problems during RSA key-generation.
    :return: A new big random prime.
    """
    assert  N % 8 == 0

    if N < 512:
        return Crypto.Util.number.getPrime(N)

    if e is not None:
        return Crypto.Util.number.getStrongPrime(N, e)
    else:
        return Crypto.Util.number.getStrongPrime(N)


def int_division_ceil(i: int, n: int) -> int:
    """
    Perform i / n and ceil the result.
    Do not perform any floating point operation,
    that could result in an overflow with
    really big numbers.

    :param i: The dividend.
    :param n: The divisor.
    :return: ceil(i / n)
    """
    if i % n == 0:
        return i // n
    else:
        return (i // n) + 1


def int_division_floor(i: int, n: int) -> int:
    """
    Perform i / n and floor the result.
    Do not perform any floating point operation,
    that could result in an overflow with
    really big numbers.

    :param i: The dividend.
    :param n: The divisor.
    :return: floor(i / n)
    """
    return i // n

