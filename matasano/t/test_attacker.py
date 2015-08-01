#!/usr/bin/env/ python
# encoding: utf-8

__author__ = 'aldur'

import unittest
import matasano.attacker


class AttackerByteAtATimeEcbTestCase(unittest.TestCase):
    def test_fill_bytes(self):
        f = matasano.attacker.AttackerByteAtATimeEcb.get_fill_bytes_len
        size = 16
        prefix = 3

        self.assertEqual(
            f(0, size),
            size - 1
        )

        self.assertEqual(
            f(size - 1, size),
            size
        )

        self.assertEqual(
            f(size, size),
            size - 1
        )

        self.assertEqual(
            f(1, size),
            size - 2
        )

        self.assertEqual(
            f(0, size, prefix),
            size - prefix - 1,
        )

        self.assertEqual(
            f(1, size, prefix),
            size - prefix - 2,
        )

        self.assertEqual(
            f(3, size, prefix),
            size - prefix - 4,
        )

        i = size
        self.assertEqual(
            f(i, size, prefix),
            (size - prefix) + (i % size) - (i % size) - 1
        )

if __name__ == '__main__':
    unittest.main()
