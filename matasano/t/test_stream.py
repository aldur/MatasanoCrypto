#!/usr/bin/env/ python
# encoding: utf-8

"""Test stream crypto."""

import unittest
import random

import matasano.stream

__author__ = 'aldur'


class StreamTestCase(unittest.TestCase):

    def test_mt19937_stream(self):
        f = matasano.stream.mt19937_stream
        key = random.randint(0, 2 ** 32 - 1)
        b = "00foobarfoobar00".encode("ascii")

        cipher = f(key, b)
        self.assertEqual(len(cipher), len(b))
        self.assertEqual(f(key, cipher), b)

if __name__ == '__main__':
    unittest.main()
