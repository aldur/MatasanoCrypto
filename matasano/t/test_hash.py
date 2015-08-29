#!/usr/bin/env/ python
# encoding: utf-8

__author__ = 'aldur'

import unittest
import hashlib

import matasano.hash


class HashTestCase(unittest.TestCase):
    def test_sha1(self):
        b = b"YELLOW_SUBMARINE!" * 30

        f = matasano.hash.sha1
        h = f(b)

        truth = hashlib.sha1()
        truth.update(b)

        self.assertEqual(truth.digest(), h)

    def test_sha1_long(self):
        b = (
            b"comment1=cooking%20MCs;userdata=foo;"
            b"comment2=%20like%20a%20pound%20of%20bacon"
        )
        f = matasano.hash.sha1

        truth = hashlib.sha1()
        truth.update(b)

        self.assertEqual(
            f(b),
            truth.digest()
        )

if __name__ == '__main__':
    unittest.main()
