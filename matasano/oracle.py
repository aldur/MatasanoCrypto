#!/usr/bin/env/ python
# encoding: utf-8

__author__ = 'aldur'

"""
The oracle related stuff.
Random generations, games, and so on.
"""

import random
import base64
import matasano.blocks
import abc


def random_aes_key() -> bytes:
    """Generate a random AES key (16 bytes)

    :return: 16 bytes.
    """
    return bytes(random.randint(0, 255) for _ in range(16))


class CheatingException(Exception):
    """
    Thrown when the oracle detects that the attacker is trying to cheat.
    """
    pass


class Oracle(object):
    """
    The base oracle abstract class.
    """
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def challenge(self, *args: bytes) -> bytes:
        """
        Challenge the oracle.
        Send him some bytes,
        and it will return some other bytes.
        Usually this function can be called only once.

        :param args: An iterable of bytes.
        :return: Some bytes.
        """
        return random.choice(args) if args else bytes()

    @abc.abstractmethod
    def guess(self, guess: bool) -> bool:
        """
        Given a guess, return true if correct.
        Usually this function can be called only once.

        :param guess: The guess done by the attacker.
        :return: True if the attacker correctly guessed.
        """
        return guess

    @abc.abstractmethod
    def experiment(self, *args: bytes) -> bytes:
        """
        Experiment with the oracle (when possible).
        Usually this function can be called how many times you need.

        :param args: An iterable of bytes.
        :return: Some bytes.
        """
        return random.choice(args) if args else bytes()


class OracleAesEcbCbc(Oracle):
    """An encryption oracle that randomly encrypts with AES ECB or AES CBC.

    Choose at random between AES ECB and AES CBC (by tossing a coin).
    Generate a random key.
    Add padding before and after b.
    Encrypt b.
    """

    def __init__(self):
        """
        Choose the cipher to use.
        """
        super(Oracle, self).__init__()
        self.cipher = matasano.blocks.aes_ecb if \
            random.random() >= 0.5 \
            else matasano.blocks.aes_cbc
        self._truth = self.cipher == matasano.blocks.aes_ecb  # using ECB encryption
        self._challenge_done = False
        self._guess_done = False

    def challenge(self, *args: bytes) -> bytes:
        """
        Generate a random key.
        Add padding before and after the first block.
        Encrypt the block.

        :param args: The block buffer to be encrypted.
            Must be a multiple of 16.
            This implementation encrypts the first one
            and ignore the others.
        :returns: An encryption of b.
        """
        assert args
        assert args[0]

        if self._challenge_done:
            raise CheatingException("Challenge can only be called once.")
        self._challenge_done = True

        b = args[0]
        key = random_aes_key()

        # Add some randomness
        b = random_bytes_random_range(5, 10) + b + random_bytes_random_range(5, 10)
        # Pad if necessary
        b = matasano.blocks.pkcs(b, 16)

        return self.cipher(key, b)

    def guess(self, guess: bool) -> bool:
        """
        Return true if the attacker correctly guesses.
        :param guess: True if attacker thinks encryption is
        ECB, false otherwise.
        :return: True if attacker correctly guesses.
        """

        if self._guess_done:
            raise CheatingException("Attackers can only guess once")
        self._guess_done = True
        return guess == self._truth

    def experiment(self, *args: bytes) -> bytes:
        """
        This oracle doesn't provide experiments.
        :param args: An iterable of bytes.
        """
        return super().experiment(args)


class OracleByteAtATimeEcb(Oracle):
    """
    An encryption oracle that encrypts each block with the
    same fixed key.
    Before encryption, he pads each block with a constant string,
    unknown to the caller.
    The attacker's goal are:
        - guess the block size of encryption, as used by the oracle (16)
        - guess the AES encryption mode (ECB)
        - discover the unknown fixed string, one byte at a time.
    """

    def __init__(self):
        super(Oracle, self).__init__()
        """
        This is a consistent AES key.
        It is the same for the whole module lifetime,
        but it's hidden from anyone (kinda)
        """
        self._consistent_key = random_aes_key()
        """
        And this is the unknown string, that the attacker has to find.
        """
        self._unknown_string = base64.b64decode(
            b"""Um9sbGluJyBpbiBteSA1LjAKV2l0a
            CBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ
            2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEa
            WQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"""
        )

        self._guess = False

    def challenge(self, *args: bytes) -> bytes:
        """
        This oracle doesn't provide a challenge.
        :param args: An iterable of bytes.
        """
        return super().challenge(args)

    def guess(self, guess: bytes) -> bool:
        """
        Compare the attacker's guess against the unknown string.

        :param guess: The attacker's guess.
        :return: True if the guess is correct.
        """
        assert guess

        if self._guess:
            raise CheatingException("Attackers can only guess once.")
        self._guess = True

        return guess == self._unknown_string

    def experiment(self, *args: bytes) -> bytes:
        """
        Return an encryption of the first block of args,
        padded with the fixed unknown string.
        :param args: An iterable of buffers to be encrypted.
        :return: An encryption of the first block.
        """
        assert args
        assert args[0]

        return matasano.blocks.aes_ecb(
            self._consistent_key,
            matasano.blocks.pad_with_buffer(
                args[0],
                self._unknown_string
            )
        )


def random_bytes_random_range(low: int, high: int) -> bytes:
    """
    Generate low to high random bytes.

    :param low: The minimum number of bytes to generate.
    :param high: The maximum (inclusive) number of bytes to generate.
    :return: A random range of random bytes s.t. low <= len(output) <= max.
    """
    return bytes(
        random.randint(0, 255)
        for _
        in range(0, random.randint(low, high))
    )
