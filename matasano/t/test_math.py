#!/usr/bin/env/ python
# encoding: utf-8

__author__ = 'aldur'

import unittest

import matasano.math


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

if __name__ == '__main__':
    unittest.main()
