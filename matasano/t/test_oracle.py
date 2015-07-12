#!/usr/bin/env/ python
# encoding: utf-8

__author__ = 'aldur'

import unittest
import matasano.oracle


class OracleTestCase(unittest.TestCase):
    def test_random_key(self):
        k = matasano.oracle.random_aes_key()
        self.assertEqual(
            len(k),
            16
        )

    def test_random_bytes_random_range(self):
        low = 5
        high = 6
        r = matasano.oracle.random_bytes_random_range(low, high)
        self.assert_(
            low <= len(r) <= high
        )

        low = 5
        high = 10
        rs = [
            matasano.oracle.random_bytes_random_range(low, high) for _ in range(500)
        ]
        self.assert_(
            low <= len(min(rs, key=lambda x: len(x))) <= high
        )
        self.assert_(
            low <= len(max(rs, key=lambda x: len(x))) <= high
        )


if __name__ == '__main__':
    unittest.main()
