#!/usr/bin/env/ python
# encoding: utf-8

__author__ = 'aldur'

"""Handle PRN generation."""

import matasano.util


class MT19937:

    """
    The Mersenne Twister PRNG.
    Code courtesy of Wikipedia
    (https://en.wikipedia.org/wiki/Mersenne_Twister)
    :param seed: The PRNG seed.
    """

    """
    Hardcoded constants:
    (w, n, m, r) = (32, 624, 397, 31)
    a = 9908B0DF16
    (u, d) = (11, FFFFFFFF16)
    (s, b) = (7, 9D2C568016)
    (t, c) = (15, EFC6000016)
    l = 18
    """

    def __init__(self, seed: int):
        # Initialize the index to 0
        self.index = 624
        self.mt = [0] * 624

        self.mt[0] = seed  # Initialize the initial state to the seed
        for i in range(1, 624):
            self.mt[i] = matasano.util.int_32_lsb(
                1812433253 * (self.mt[i - 1] ^ self.mt[i - 1] >> 30) + i
            )

    def extract_number(self) -> int:
        """
        Extract a tempered value based on MT[index]
        calling twist() every n numbers

        :return: A new PRN.
        """
        if self.index >= 624:
            self.twist()

        y = self.mt[self.index]

        # Right shift by 11 bits
        y ^= y >> 11
        # Shift y left by 7 and take the bitwise and of 2636928640
        y ^= y << 7 & 2636928640
        # Shift y left by 15 and take the bitwise and of y and 4022730752
        y ^= y << 15 & 4022730752
        # Right shift by 18 bits
        y ^= y >> 18

        self.index += 1

        return matasano.util.int_32_lsb(y)

    def twist(self):
        """
        Generate the next n values.
        """
        for i in range(0, 624):
            # Get the most significant bit and add it to the less significant
            # bits of the next number
            y = matasano.util.int_32_lsb(
                (self.mt[i] & 0x80000000) +
                (self.mt[(i + 1) % 624] & 0x7fffffff)
            )
            self.mt[i] = self.mt[(i + 397) % 624] ^ y >> 1

            if y % 2 != 0:
                self.mt[i] ^= 0x9908b0df
        self.index = 0
