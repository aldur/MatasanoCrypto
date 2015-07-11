#!/usr/bin/env/ python
# encoding: utf-8

__author__ = 'aldur'

import matasano.util
import unittest


class UtilTestCase(unittest.TestCase):
    def test_hex_to_base64(self):
        self.assertEqual(
            matasano.util.hex_to_b64(
                bytearray.fromhex(
                    "49276d206b696c6c696e6720796f75722062"
                    "7261696e206c696b65206120706f69736f6e"
                    "6f7573206d757368726f6f6d")
            ),
            b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        )

    def test_xor(self):
        a = bytearray.fromhex("1c0111001f010100061a024b53535009181c")
        b = bytearray.fromhex("686974207468652062756c6c277320657965")
        c = bytearray(matasano.util.xor(a, b))
        truth = bytearray.fromhex("746865206b696420646f6e277420706c6179")

        self.assertEqual(c, truth)

    def test_xor_char(self):
        f = matasano.util.xor_char
        p_text = b"foo"

        self.assertEqual(
            p_text,
            f(f(p_text, chr(42)), chr(42))
        )
        self.assertEqual(
            p_text,
            f(p_text, chr(0))
        )

        truth = bytes.fromhex(
            "1b37373331363f78151b7f2b783431333d"
            "78397828372d363c78373e783a393b3736"
        )
        p_text = "Cooking MC's like a pound of bacon".encode("ascii")
        k = 'X'

        self.assertEqual(
            f(p_text, k),
            truth
        )

    def test_repeating_xor(self):
        lines = "Burning 'em, if you ain't quick and nimble\n" \
                "I go crazy when I hear a cymbal".encode("ascii")
        key = "ICE".encode("ascii")
        truth = bytes.fromhex("0b3637272a2b2e63622c2e69692a23693a2a3c632420"
                              "2d623d63343c2a26226324272765272"
                              "a282b2f20430a652e2c652a3124333a653e2b2027630"
                              "c692b20283165286326302e27282f")
        self.assertEqual(truth, matasano.util.repeating_xor(lines, key))


if __name__ == '__main__':
    unittest.main()
