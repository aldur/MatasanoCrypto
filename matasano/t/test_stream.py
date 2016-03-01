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

    def test_rc4_stream(self):
        f = matasano.stream.rc4_stream
        key = bytes.fromhex('6162636465666768696A6B6C6D6E6F70')
        b = b"foobar"

        cipher = f(key, b)
        self.assertEqual(len(cipher), len(b))
        self.assertEqual(f(key, cipher), b)

        """
        echo -ne "foobar" | \
            openssl rc4 -K "6162636465666768696A6B6C6D6E6F70" -e -nopad -nosalt  | \
            xxd -ps
        """
        self.assertEqual(cipher, bytes.fromhex('caaf2cbfd334'))

if __name__ == '__main__':
    unittest.main()
