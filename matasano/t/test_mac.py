#!/usr/bin/env/ python
# encoding: utf-8

__author__ = 'aldur'

import unittest

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


if __name__ == '__main__':
    unittest.main()
