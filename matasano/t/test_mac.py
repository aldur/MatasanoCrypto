#!/usr/bin/env/ python
# encoding: utf-8

"""
Test the MACs.
"""

import unittest
import hmac
import hashlib

import matasano.mac

__author__ = 'aldur'


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

    def test_cbc_mac(self):
        k = b'secret_key_12345'
        b = b'a plaintext mess'

        # Got it as follows:
        """
        $ echo -n 'a plaintext mess' | \
            openssl enc -e -aes-128-cbc \
            -K $(echo -n secret_key_12345 | xxd -ps) \
            -iv 0000000000000000 -nosalt -nopad | \
            tail -c 16 | xxd -ps -c 16
        """
        truth = bytes.fromhex('ecb983430bf5b6184fafc91fd97af552')

        f = matasano.mac.aes_cbc_mac
        self.assertEqual(
            f(k, b),
            truth
        )

    def test_cbc_mac_pad(self):
        k = b'YELLOW SUBMARINE'
        b = b"alert('MZA who was that?');\n"
        truth = bytes.fromhex('296b8d7cb78a243dda4d0a61d33bbdd1')

        f = matasano.mac.aes_cbc_mac
        self.assertEqual(
            f(k, b, pad=True),
            truth
        )

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
