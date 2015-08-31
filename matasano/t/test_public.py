#!/usr/bin/env/ python
# encoding: utf-8

__author__ = 'aldur'

import unittest

import matasano.public


class PublicTestCase(unittest.TestCase):
    def test_dh(self):
        f = matasano.public.dh_keys
        p = 23
        g = 5

        _, _, priv, pub = f(p=p, g=g)
        self.assertEqual(
            pow(g, priv, p), pub
        )

    def test_dh_default(self):
        f = matasano.public.dh_keys

        p, g, priv, pub = f()
        self.assertEqual(
            pow(g, priv, p), pub
        )


if __name__ == '__main__':
    unittest.main()
