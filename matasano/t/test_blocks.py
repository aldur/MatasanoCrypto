#!/usr/bin/env/ python
# encoding: utf-8

__author__ = 'aldur'

import unittest
import matasano.blocks


class BlocksTestCase(unittest.TestCase):
    def test_split_blocks(self):
        f = matasano.blocks.split_blocks
        b = "this is a test".encode("ascii")
        k_len = 3

        blocks = f(b, k_len)
        self.assertEqual(
            len(blocks),
            k_len
        )
        self.assertEqual(
            sum(len(i) for i in blocks),
            len(b)
        )

        l = list()
        for i in range(len(blocks[0])):
            for j in range(len(blocks)):
                try:
                    l.append(blocks[j][i])
                except IndexError:
                    pass
        l = bytes(l)

        self.assertEqual(
            b, l
        )
        self.assertEqual(
            b.decode("ascii"),
            l.decode("ascii")
        )


if __name__ == '__main__':
    unittest.main()
