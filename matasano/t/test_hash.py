#!/usr/bin/env/ python
# encoding: utf-8

"""
Test the hash functions.
"""

import unittest
import binascii
import hashlib

import matasano.hash
import matasano.blocks

__author__ = 'aldur'


class HashTestCase(unittest.TestCase):
    def test_sha1(self):
        b = b"YELLOW_SUBMARINE!" * 30

        f = matasano.hash.SHA1
        h = f(b)

        truth = hashlib.sha1()
        truth.update(b)

        self.assertEqual(truth.digest(), h)

    def test_sha1_long(self):
        b = (
            b"comment1=cooking%20MCs;userdata=foo;"
            b"comment2=%20like%20a%20pound%20of%20bacon"
        )
        f = matasano.hash.SHA1

        truth = hashlib.sha1()
        truth.update(b)

        self.assertEqual(
            f(b),
            truth.digest()
        )

    def test_md4(self):
        f = matasano.hash.MD4

        for message, truth in {
            b"": b"31d6cfe0d16ae931b73c59d7e0c089c0",
            b"a": b"bde52cb31de33e46245e05fbdbd6fb24",
            b"abc": b"a448017aaf21d8525fc10ae87aa6729d",
            b"message digest": b"d9130a8164549fe818874806e1c7014b",
            b"abcdefghijklmnopqrstuvwxyz": b"d79e1c308aa5bbcdeea8ed63df412da9",
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            b"abcdefghijklmnopqrstuvwxyz0123456789":
                b"043f8582f241db351ce627e153e7f0e4",
            b"123456789012345678901234567890123456789"
            b"01234567890123456789012345678901234567890":
                b"e33b4ddc9c38f2199c3e7b164fcc0536",
        }.items():
            self.assertEqual(
                binascii.hexlify(
                    f(message)
                ),
                truth
            )

    def test_h_AES128(self):
        # Test for correct length and runtime failures
        f = matasano.hash.h_AES128
        h = f(b"foobar")
        self.assertEqual(len(h), 8)
        h = f(b"foobar" * 38, b"a initial state")
        self.assertEqual(len(h), 8)

    def test_weak_collision(self):
        f = matasano.hash.weak_iterated_hash
        self.assertEqual(
            f((118).to_bytes(16, 'little')),
            f((351).to_bytes(16, 'little'))
        )

        # Mix IV and block concatenation
        self.assertEqual(
            f((125).to_bytes(16, 'little'), f((118).to_bytes(16, 'little'))),
            f((351).to_bytes(16, 'little') + (402).to_bytes(16, 'little')),
        )


if __name__ == '__main__':
    unittest.main()
