#!/usr/bin/env/ python
# encoding: utf-8

__author__ = 'aldur'

"""
Public cryptography tools.
"""

import random
import math

import matasano.hash
import matasano.blocks
import matasano.util

dh_nist_p = int(
    """0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd12902"""
    """4e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a4"""
    """31b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42"""
    """e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe"""
    """649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8"""
    """fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d6"""
    """70c354e4abc9804f1746c08ca237327ffffffffffffffff""",
    base=16
)
dh_nist_g = 2


def dh_keys(p: int=dh_nist_p, g: int=dh_nist_g) -> tuple:
    """
    Generate Diffie-Hellman keys.

    :param p: The group modulo.
    :param g: A primitive root of p.
    :return: p, g, the private and the public DH keys.
    """
    private_key = random.randint(0, p)
    public_key = pow(g, private_key, p)

    return p, g, private_key, public_key


class DHEntity:
    """
    The entity initiating the DH key exchange protocol.
    """

    @staticmethod
    def session_key_to_16_aes_bytes(k: int) -> bytes:
        """
        Convert a DH session key to an AES-eligible 16 bytes key.
        Encode the key to little endian bytes,
        hash them and return the 16-bytes prefix.

        :param k: The session key.
        :return: An AES key derived from k.
        """
        assert k >= 0

        h = matasano.hash.SHA1
        if k == 0:
            digest = h(bytes(1))
        elif k == 1:
            digest = h(k.to_bytes(1, 'little'))
        else:
            digest = h(
                k.to_bytes(
                    math.ceil(math.log(k, 256)),
                    'little'
                )
            )

        assert len(digest) > 16
        return digest[:16]

    @staticmethod
    def decipher_received_message(k: bytes, ciphertext: bytes) -> bytes:
        """
        Decrypt the received message and return the contained plaintext.

        :param k: The key.
        :param ciphertext: The ciphertext.
        :return: The plaintext.
        """
        iv, ciphertext = ciphertext[-16:], ciphertext[:-16]
        plaintext, _ = matasano.blocks.aes_cbc(
            key=k,
            b=ciphertext,
            iv=iv,
            decrypt=True
        )
        return plaintext

    def __init__(self):
        self._keys = None
        self._session_key = -1  # Invalid, has to be >= 0

    def dh_protocol(self, receiver, p: int=None, g: int=None):
        """
        Generate a new pair of keys.
        Initiate a new DH-key exchange protocol.

        :param receiver: The responding entity of the DH-protocol.
        :param p: The group modulo.
        :param g: A primitive root of p.
        """
        assert receiver
        assert receiver != self

        if p and g:
            _, _, a, pub_a = self._keys = dh_keys(p, g)
        else:
            p, g, a, pub_a = self._keys = dh_keys()
        pub_b = receiver.dh_protocol_respond(p, g, pub_a)
        self._session_key = pow(pub_b, a, p)

    def dh_protocol_respond(self, p: int, g: int, pub_a: int) -> int:
        """
        Handle a DH protocol request.
        Generate a new pair keys,
        return the public one to the caller,
        and store the session key computed
        from the caller's public key.

        :param p: The group modulo.
        :param g: A primitive root of p.
        :param pub_a: The caller's DH public key.
        """
        _, _, b, pub_b = self._keys = dh_keys(p, g)
        self._session_key = pow(pub_a, b, p)
        return pub_b

    def send_and_receive(self, receiver, message: bytes) -> bytes:
        """
        Send an encrypted message as follows:
        - key = SHA1(session_key)[:16]
        - iv = random IV
        - message
        send: AES_CBC(message) || iv

        :param receiver: The receiver.
        :param message:  The message to be sent.
        :return: The received answer (if any).
        """
        key = DHEntity.session_key_to_16_aes_bytes(
            self._session_key
        )
        ciphertext, iv = matasano.blocks.aes_cbc(
            key=key,
            b=message,
            random_iv=True
        )
        ciphertext = receiver.receive_and_send_back(ciphertext + iv)
        plaintext = DHEntity.decipher_received_message(key, ciphertext)

        return plaintext

    def receive_and_send_back(self, ciphertext: bytes) -> bytes:
        """
        Receive an encrypted message,
        decrypt it, generate a new random IV,
        encrypt it again and send it back.

        :param ciphertext: The received ciphertext.
        :return: A new ciphertext, whose IV vector has been changed.
        """
        key = DHEntity.session_key_to_16_aes_bytes(
            self._session_key
        )
        plaintext = DHEntity.decipher_received_message(key, ciphertext)
        ciphertext, iv = matasano.blocks.aes_cbc(
            key,
            plaintext,
            random_iv=True
        )
        return ciphertext + iv


class DHAckEntity(DHEntity):
    """
    Before starting the DH protocol send the group parameters
    and wait for an ACK.
    """

    def __init__(self):
        super(DHAckEntity, self).__init__()
        self._p, self._g = dh_nist_p, dh_nist_g

    def set_group_parameters(self, p: int, g: int):
        """
        Setup the group parameters and return.

        :param p: The group modulo.
        :param g: A primitive root of p.
        :return: True.
        """
        self._p, self._g = p, g
        return True

    def dh_protocol(self, receiver, p: int=None, g: int=None):
        """
        Send the group parameters to the receiver and wait for an ACK.
        Generate a new pair of keys.
        Initiate a new DH-key exchange protocol.

        :param p: The group modulo.
        :param g: A primitive root of p.
        :param receiver: The responding entity of the DH-protocol.
        """
        receiver.set_group_parameters(p, g)
        super(DHAckEntity, self).dh_protocol(receiver, p, g)

    def dh_protocol_respond(self, p: int, g: int, pub_a: int) -> int:
        """
        Handle a DH protocol request.
        Generate a new pair keys,
        return the public one to the caller,
        and store the session key computed
        from the caller's public key.

        :param p: The group modulo.
        :param g: A primitive root of p.
        :param pub_a: The caller's DH public key.
        """
        assert self._p == p
        assert self._g == g
        return super(DHAckEntity, self).dh_protocol_respond(self._p, self._g, pub_a)
