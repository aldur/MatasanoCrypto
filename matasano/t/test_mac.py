#!/usr/bin/env/ python
# encoding: utf-8

__author__ = 'aldur'

import unittest
import hmac
import hashlib

import matasano.mac


class MacTestCase(unittest.TestCase):
    def test_sha1_secret_prefix(self):
        # Foolish tests, for now.
        f = matasano.mac.sha1_secret_prefix

        m_one = f(b"KEY", b"YELLOW_SUBMARINE")
        m_two = f(b"FOO", b"YELLOW_SUBMARINE")

        self.assertNotEqual(m_one, m_two)

    def test_md4_secret_prefix(self):
        # Foolish tests, for now.
        f = matasano.mac.md4_secret_prefix

        m_one = f(b"KEY", b"YELLOW_SUBMARINE")
        m_two = f(b"FOO", b"YELLOW_SUBMARINE")

        self.assertNotEqual(m_one, m_two)

    def test_sha1_hmac(self):
        for k in [b"SECRET_KEY", bytes(200)]:
            m = b"Yep, this is a message."

            f = matasano.mac.hmac_sha1
            signature = f(k, m)

            truth = hmac.HMAC(
                k, m, hashlib.sha1
            ).digest()

            self.assertEqual(
                signature, truth
            )


if __name__ == '__main__':
    unittest.main()
