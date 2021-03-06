#!/usr/bin/env/ python
# encoding: utf-8

"""
Test math-related tools.
"""

import unittest
import matasano.math

__author__ = 'aldur'


class MathTestCase(unittest.TestCase):
    def test_extended_gcd(self):
        egcd = matasano.math.extended_gcd

        self.assertEqual(
            egcd(7, 9)[0],
            1
        )

        self.assertEqual(
            egcd(7, 7)[0],
            7
        )

        self.assertEqual(
            egcd(7, 1)[0],
            1
        )

        self.assertEqual(
            egcd(7, 9),
            (1, 4, -3)
        )

    def test_modinv(self):
        f = matasano.math.modinv
        self.assertEqual(
            f(5, 9),
            2
        )

        self.assertEqual(
            f(7, 9),
            4
        )

    def test_int_cube_root(self):
        f = matasano.math.integer_cube_root
        self.assertEqual(
            f(125), 5
        )
        self.assertEqual(
            f(126), 5
        )

if __name__ == '__main__':
    unittest.main()
