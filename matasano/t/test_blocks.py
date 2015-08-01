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

    def test_pkcs(self):
        b = "YELLOW SUBMARINE".encode("ascii")

        size = 20
        padded = matasano.blocks.pkcs(b, size)
        self.assertEqual(len(padded), size)
        self.assertEqual(padded, b + b"\x04" * 4)

        size = 16
        padded = matasano.blocks.pkcs(b, size)
        print(padded)
        self.assertEqual(len(padded), size * 2)
        self.assertEqual(padded, b + (b"\x10" * size))

    def test_un_pkcs(self):
        b = "YELLOW SUBMARINE".encode("ascii")

        size = 20
        padded = matasano.blocks.pkcs(b, size)
        un_padded = matasano.blocks.un_pkcs(padded)
        self.assertEqual(b, un_padded)

        size = 16
        padded = matasano.blocks.pkcs(b, size)
        un_padded = matasano.blocks.un_pkcs(padded)
        self.assertEqual(b, un_padded)

    def test_aes_ecb(self):
        f = matasano.blocks.aes_ecb
        key = "YELLOW SUBMARINE".encode("ascii")
        b = "00foobarfoobar00".encode("ascii")

        self.assertEqual(
            f(key, f(key, b), decrypt=True),
            b
        )

    def test_aes_cbc(self):
        f = matasano.blocks.aes_cbc
        key = "YELLOW SUBMARINE".encode("ascii")
        b = "00foobarfoobar00".encode("ascii")

        self.assertEqual(
            f(key, f(key, b), decrypt=True),
            b
        )

    def test_bytes_in_blocks(self):
        f = matasano.blocks.bytes_in_blocks
        size = 16

        self.assertEqual(
            f(size, 0),
            slice(0, size)
        )

        self.assertEqual(
            f(size, 1),
            slice(size, size * 2)
        )

    def test_bytes_to_block(self):
        f = matasano.blocks.bytes_to_block
        size = 16

        self.assertEqual(
            f(size, 0),
            slice(0, size)
        )

        self.assertEqual(
            f(size, 1),
            slice(0, size * 2)
        )

        self.assertEqual(
            f(size, 10),
            slice(0, size * 11)
        )

    def test_ith_byte_in_block(self):
        f = matasano.blocks.ith_byte_block
        size = 16

        self.assertEqual(
            f(size, 0),
            0
        )

        self.assertEqual(
            f(size, 1),
            0
        )

        self.assertEqual(
            f(size, size),
            1
        )

        self.assertEqual(
            f(size, size * 2),
            2
        )


if __name__ == '__main__':
    unittest.main()
