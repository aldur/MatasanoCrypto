#!/usr/bin/env python
# encoding: utf-8

__author__ = "aldur"

"""Buffer/string/bytes stats function will stay here."""

import math
import collections
import itertools
import sys

import matasano.util

"""
Distribution of single characters in the english language.
"""
english_frequencies = {
    'a': 0.08167,
    'b': 0.01492,
    'c': 0.02782,
    'd': 0.04253,
    'e': 0.12702,
    'f': 0.02228,
    'g': 0.02015,
    'h': 0.06094,
    'i': 0.06966,
    'j': 0.00153,
    'k': 0.00772,
    'l': 0.04025,
    'm': 0.02406,
    'n': 0.06749,
    'o': 0.07507,
    'p': 0.01929,
    'q': 0.00095,
    'r': 0.05987,
    's': 0.06327,
    't': 0.09056,
    'u': 0.02758,
    'v': 0.00978,
    'w': 0.02360,
    'x': 0.00150,
    'y': 0.01974,
    'z': 0.00074,
}


def char_distribution(string: str) -> collections.Counter:
    """Given an ascii string, return the distribution of its characters
    as a percentage of the total string length.

    :param string: the string to be analyzed
    :returns: the characters distribution of the string
    """
    assert string

    string = string.lower()
    c = collections.Counter(string)

    return c


def chi_squared(s: str) -> float:
    """Given a string, calculate its Chi-Squared statistic
    with respect to the known english letter frequencies distribution.
    Please note that this slightly modifier version penalizes non-alpha
    ascii characters.

    :param s: string to be analyzed
    :returns: The Chi-Squared Statistic of input string.

    """
    assert s

    c = char_distribution(s)
    # Counter[NOT_IN_COUNTER] = 0, useful! :)

    e = {
        k: v * float(len(s))
        for k, v
        in english_frequencies.items()
    }

    return sum(
        math.pow(c[k] - e[k], 2) / e[k]
        for k in e
    ) + sum(  # Penalize non-alpha ascii chars
        math.pow(c[k], 4) for k in set(c.keys()) - set(e.keys()) - {' '}
    )


def most_likely_xor_chars(b: bytes, count: int=1) -> tuple:
    """Find the most likely char used to xor b.

    :param b: An ASCII bytes string.
    :param count: The number of chars to be returned.
    :return: The most likely character used in the XOR.
    """
    assert b

    def rank(i: int) -> int:
        """
        Inner ranking function.
        XOR the whole buffer with the given integer,
        decode it as ASCII and rank it by using
        CHI squared.

        :param i: The XOR key.
        :return: The CHI Squared value of the decrypted string.
        """
        try:
            return chi_squared(
                matasano.util.xor_char(b, chr(i)).decode("ascii")
            )
        except UnicodeDecodeError:
            return sys.maxsize

    return tuple(
        chr(c)
        for c
        in sorted(range(256), key=rank)[:count]
    )


def most_likely_key_length(b: bytes) -> int:
    """
    Iterate through the possible key lengths.
    Return the most likely one according to the Hamming distance.
    Specifically, take any possible combination of the first 5 blocks.
    Compare them through hamming distance, normalize and store the sum.
    Return the minimum.

    :param b: A buffer of bytes.
    :returns: The most likely key length used to encrypt the buffer.
    """
    # 2 and 41 are "advised" by the Matasano guys
    return min(
        range(2, 41),
        key=lambda i: sum(
            hamming_d(
                b[p[0] * i:(p[0] + 1) * i],
                b[p[1] * i:(p[1] + 1) * i]
            ) / float(i)
            for p in itertools.combinations(range(0, 5), 2)
        ) / float(5.0 * 4.0 / 2.0)
    )


def count_set_bits(n: int) -> int:
    """Count those bits set (to 1) in n

    :param n: integer
    :returns: number of 1s in n

    """
    assert 0 <= n <= 255
    return sum(
        1 for i in range(8)
        if (n >> i) % 2 == 1
    )


def hamming_d(a: bytes, b: bytes) -> int:
    """
    Compute the Hamming Distance between a and b.
    We compute it by counting the number of different bits.

    :param a: Some bytes.
    :param b: Some bytes.
    :return: The number of bits a and b differ for.
    """
    assert len(a) == len(b)
    return sum(
        count_set_bits(a[i] ^ b[i])
        for i in range(len(a))
    )
