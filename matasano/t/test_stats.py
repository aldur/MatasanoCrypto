#!/usr/bin/env/ python
# encoding: utf-8

"""
Test the stats.
"""

import unittest
import matasano.stats

__author__ = 'aldur'


class StatsTestCase(unittest.TestCase):
    def test_count_set_bits(self):
        f = matasano.stats.count_set_bits
        self.assertEqual(f(0), 0)
        self.assertEqual(f(1), 1)
        self.assertEqual(f(3), 2)
        self.assertEqual(f(11), 3)

    def test_hamming_d(self):
        f = matasano.stats.hamming_d
        self.assertEqual(
            f(
                b"this is a test",
                b"wokka wokka!!!"
            ), 37
        )


if __name__ == '__main__':
    unittest.main()
