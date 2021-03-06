#!/usr/bin/env/ python
# encoding: utf-8

"""
Test the public key related crypto.
"""

import unittest

import matasano.public
import matasano.hash

__author__ = 'aldur'


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

    def test_dh_protocol(self):
        alice = matasano.public.DHEntity()
        bob = matasano.public.DHEntity()

        alice.dh_protocol(bob)
        self.assertEqual(
            alice._session_key,
            bob._session_key
        )

    def test_dh_protocol_bad_g(self):
        alice = matasano.public.DHEntity()
        bob = matasano.public.DHEntity()

        alice.dh_protocol(
            bob,
            p=matasano.public.dh_nist_p,
            g=matasano.public.dh_nist_p - 1
        )
        self.assertEqual(
            alice._session_key,
            bob._session_key
        )

    def test_dh_message(self):
        alice = matasano.public.DHEntity()
        bob = matasano.public.DHEntity()
        alice.dh_protocol(bob)

        message = b"MessageInABottle"
        answer = alice.send_and_receive(bob, message)
        self.assertEqual(
            message,
            answer
        )

    def test_dh_ack_message(self):
        alice = matasano.public.DHAckEntity()
        bob = matasano.public.DHAckEntity()
        alice.dh_protocol(bob)

        message = b"MessageInABottle"
        answer = alice.send_and_receive(bob, message)
        self.assertEqual(
            message,
            answer
        )

    def test_srp(self):
        password = b"A simple secret password."
        server = matasano.public.SRPServer(password)
        client = matasano.public.SRPClient(password, server)

        self.assertTrue(client.srp_protocol())

    def test_simplified_srp(self):
        password = b"A simple secret password."
        server = matasano.public.SimplifiedSRPServer(password)
        client = matasano.public.SimplifiedSRPClient(password, server)

        self.assertTrue(client.srp_protocol())

    def test_rsa_textbook(self):
        private, public = matasano.public.rsa_keys()
        message = b"Textbook"

        c = matasano.public.rsa_encrypt(public, message)
        self.assertEqual(
            matasano.public.rsa_decrypt(private, c),
            message
        )

    def test_rsa_signature(self):
        private, public = matasano.public.rsa_keys()
        message = matasano.hash.SHA256(b"Textbook" * 1000)

        s = matasano.public.rsa_sign(private, message)
        self.assertTrue(
            matasano.public.rsa_verify(
                public, message, s
            )
        )

    def test_dsa_signature(self):
        private, public = matasano.public.dsa_keys()
        message = b"Textbook" * 1000

        signature = matasano.public.dsa_sign(
            message,
            private
        )
        self.assertTrue(
            matasano.public.dsa_verify(
                message, signature, public
            )
        )

if __name__ == '__main__':
    unittest.main()
