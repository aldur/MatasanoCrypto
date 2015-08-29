#!/usr/bin/env/ python
# encoding: utf-8

__author__ = 'aldur'

import unittest
import hashlib

import matasano.hash


class HashTestCase(unittest.TestCase):
    def test_sha1(self):
        b = b"YELLOW_SUBMARINE!"

        f = matasano.hash.sha1
        h = f(b)

        truth = hashlib.sha1()
        truth.update(b)

        self.assertEqual(truth.digest(), h)


if __name__ == '__main__':
    unittest.main()
