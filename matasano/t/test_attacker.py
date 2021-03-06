#!/usr/bin/env/ python
# encoding: utf-8

"""
Test the attackers.
"""

import unittest
import random

import matasano.attacker

__author__ = 'aldur'


class AttackerByteAtATimeEcbTestCase(unittest.TestCase):
    def test_fill_bytes(self):
        f = matasano.attacker.AttackerByteAtATimeEcb.get_fill_bytes_len
        size = 16
        prefix = 3

        self.assertEqual(
            f(0, size),
            size - 1
        )

        self.assertEqual(
            f(size - 1, size),
            size
        )

        self.assertEqual(
            f(size, size),
            size - 1
        )

        self.assertEqual(
            f(1, size),
            size - 2
        )

        self.assertEqual(
            f(0, size, prefix),
            size - prefix - 1,
        )

        self.assertEqual(
            f(1, size, prefix),
            size - prefix - 2,
        )

        self.assertEqual(
            f(3, size, prefix),
            size - prefix - 4,
        )

        i = size
        self.assertEqual(
            f(i, size, prefix),
            (size - prefix) + (i % size) - (i % size) - 1
        )


class AttackerMT19937CloneTestCase(unittest.TestCase):
    def test_untemper_one(self):
        f = matasano.attacker.AttackerMT19937Clone.untemper_one
        x = random.randint(0, (2 ** 32) - 1)
        y = x ^ x >> 11
        self.assertEqual(x, f(y))

    def test_untemper_two(self):
        f = matasano.attacker.AttackerMT19937Clone.untemper_two
        x = random.randint(0, (2 ** 32) - 1)
        y = x ^ x << 7 & 2636928640
        self.assertEqual(x, f(y))

    def test_untemper_three(self):
        f = matasano.attacker.AttackerMT19937Clone.untemper_three
        x = random.randint(0, (2 ** 32) - 1)
        y = x ^ x << 15 & 4022730752
        self.assertEqual(x, f(y))

    def test_untemper_four(self):
        f = matasano.attacker.AttackerMT19937Clone.untemper_four
        x = random.randint(0, (2 ** 32) - 1)
        y = x ^ (x >> 18)
        self.assertEqual(x, f(y))

if __name__ == '__main__':
    unittest.main()
